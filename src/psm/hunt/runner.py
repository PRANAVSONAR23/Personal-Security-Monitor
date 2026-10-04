"""Hunt runner — artifacts from the latest snapshot, analyzers over them, findings out.

Hunt is neither poll nor stream (HLD D2/D3): it re-reads what inventory already
stored and asks "is any of this bad?". It touches no device, so it can be re-run
freely after an analyzer changes.

Findings are upserted on (artifact, analyzer, analyzer_version, rule), so
re-running the same analyzer version is idempotent; bumping a version produces a
new row and the delta is meaningful.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from psm.core.models import (
    Artifact,
    Device,
    Event,
    Finding,
    utcnow_iso,
)
from psm.hunt import apk as apk_analyzers
from psm.hunt.base import Analyzer
from psm.store.db import transaction
from psm.store.queries import (
    load_latest_snapshot_id,
    load_snapshot_items,
    upsert_artifact,
    upsert_finding,
)

# Findings at or above this verdict are promoted into the chained event log, so
# the timeline carries them alongside inventory changes.
PROMOTE = frozenset({"malicious"})
PROMOTE_SUSPICIOUS_CONFIDENCE = frozenset({"high"})


@dataclass(slots=True)
class HuntResult:
    snapshot_id: int
    artifacts: int
    findings: list[Finding] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)


class HuntError(RuntimeError):
    pass


def default_analyzers() -> tuple[Analyzer, ...]:
    return apk_analyzers.ANALYZERS


def run(
    conn: sqlite3.Connection,
    device: Device,
    *,
    analyzers: tuple[Analyzer, ...] | None = None,
    snapshot_id: int | None = None,
) -> HuntResult:
    if device.id is None:
        raise HuntError("device must be persisted before hunting")

    snap = snapshot_id or load_latest_snapshot_id(
        conn, device.id, kinds=("baseline", "scan", "after")
    )
    if snap is None:
        raise HuntError(f"no snapshots for {device.name!r} — run `psm baseline` first")

    active = analyzers if analyzers is not None else default_analyzers()
    items = load_snapshot_items(conn, snap)

    # Granted permissions, grouped by package, so the permission analyzer sees
    # everything it needs in one payload and stays a pure function.
    granted: dict[str, set[str]] = {}
    for item in items:
        if item.category != "permission":
            continue
        pl = item.payload
        if pl.get("granted") and isinstance(pl.get("pkg"), str):
            granted.setdefault(pl["pkg"], set()).add(str(pl.get("permission")))

    result = HuntResult(snapshot_id=snap, artifacts=0)
    now = utcnow_iso()

    with transaction(conn):
        for item in items:
            artifact, payload = _as_artifact(device.id, item.category, item.payload, now)
            if artifact is None:
                continue
            if artifact.kind == "apk":
                payload["granted_permissions"] = sorted(granted.get(payload.get("id", ""), ()))
            upsert_artifact(conn, artifact)
            result.artifacts += 1

            for analyzer in active:
                if artifact.kind not in analyzer.accepts:
                    continue
                for finding in analyzer.analyze(artifact, payload):
                    finding.ts = now
                    upsert_finding(conn, finding)
                    result.findings.append(finding)

    return result


def _as_artifact(
    device_id: int, category: str, payload: dict[str, Any], now: str
) -> tuple[Artifact | None, dict[str, Any]]:
    """Map an inventory item to an analyzable artifact, or None if it is not one."""
    if category == "application":
        pkg = payload.get("id")
        if not isinstance(pkg, str):
            return None, payload
        return (
            Artifact(
                device_id=device_id,
                kind="apk",
                subject_key=f"pkg:{pkg}",
                sha256=None,  # the APK itself is only hashed if it is pulled
                size=None,
                local_path=payload.get("apk_path"),
                first_seen=now,
                last_seen=now,
            ),
            dict(payload),
        )

    if category == "file":
        path = payload.get("path")
        if not isinstance(path, str):
            return None, payload
        sha = payload.get("sha256")
        return (
            Artifact(
                device_id=device_id,
                kind="apk" if payload.get("installable") else "file",
                subject_key=f"file:{path}",
                sha256=sha if isinstance(sha, str) else None,
                size=payload.get("size") if isinstance(payload.get("size"), int) else None,
                local_path=None,
                first_seen=now,
                last_seen=now,
            ),
            dict(payload),
        )

    return None, payload


def promotable(finding: Finding) -> bool:
    """Whether a finding is severe enough to enter the chained event log."""
    if finding.verdict in PROMOTE:
        return True
    return finding.verdict == "suspicious" and finding.confidence in PROMOTE_SUSPICIOUS_CONFIDENCE
