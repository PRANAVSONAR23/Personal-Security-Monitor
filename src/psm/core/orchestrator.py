"""Orchestrator — device resolution, snapshot lifecycle, diff wiring.

Poll mode only. Stream sources (netflow, ESF) have their own supervisor and never
pass through here — a stream has no previous snapshot to diff against (HLD D3).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from psm import __version__
from psm.collectors.base import Collector, Normalizer
from psm.core.chain import append_events
from psm.core.diff import diff
from psm.core.models import Alert, Device, Event, Snapshot, utcnow_iso
from psm.core.rules import AlertIntent, Rule, load_builtin_rules
from psm.core.rules import evaluate as evaluate_rules
from psm.enrich.known_good import bulk_lookup as known_good_lookup
from psm.store.db import transaction
from psm.store.queries import (
    insert_alert,
    insert_snapshot,
    load_item_payload,
    load_snapshot,
    load_snapshot_index,
)


class OrchestratorError(RuntimeError):
    pass


@dataclass(slots=True)
class SnapshotResult:
    snapshot: Snapshot
    events: list[Event]
    prior_snapshot_id: int | None
    alerts: list[Alert] = field(default_factory=list)


class CollectorFactory(Protocol):
    def __call__(self, **kwargs: Any) -> tuple[Collector, Normalizer]: ...


_REGISTRY: dict[str, CollectorFactory] = {}


def register(platform: str, factory: CollectorFactory) -> None:
    _REGISTRY[platform] = factory


def _resolve(device: Device, **kwargs: Any) -> tuple[Collector, Normalizer]:
    factory = _REGISTRY.get(device.platform)
    if factory is None:
        raise OrchestratorError(f"no collector registered for platform {device.platform!r}")
    return factory(**kwargs)


def take_snapshot(
    conn: sqlite3.Connection,
    device: Device,
    *,
    kind: str,
    modules: set[str] | None = None,
    rules: list[Rule] | None = None,
    suppress_known_good: bool = False,
    **collector_kwargs: Any,
) -> SnapshotResult:
    """Collect + normalize + persist. For non-baseline kinds, also diff and alert."""
    if device.id is None:
        raise OrchestratorError("device must be persisted before taking a snapshot")

    collector, normalizer = _resolve(device, **collector_kwargs)

    planned = collector.capabilities(device)
    target = (modules & planned) if modules else planned
    bundle = collector.collect(device, target)
    items = normalizer.normalize(bundle)

    # F1: the stored capability set is what actually collected, never what was
    # planned or declared. A module that failed is absent here, so the diff skips
    # its category instead of reporting every item in it as removed.
    snapshot = Snapshot(
        device_id=device.id,
        kind=kind,  # type: ignore[arg-type]
        capabilities=set(bundle.collected),
        tool_version=__version__,
        taken_at=bundle.taken_at,
        gaps=bundle.gaps,
    )

    events: list[Event] = []
    alerts: list[Alert] = []
    prior_id: int | None = None
    active_rules = rules if rules is not None else load_builtin_rules()

    with transaction(conn):
        insert_snapshot(conn, snapshot, items)

        if kind != "baseline":
            prior_id = _previous_snapshot_id(conn, device.id, snapshot.id)
            if prior_id is not None:
                prior_snap = load_snapshot(conn, prior_id)
                idx_a = load_snapshot_index(conn, prior_id)
                assert snapshot.id is not None
                idx_b = load_snapshot_index(conn, snapshot.id)
                events = diff(prior_snap, idx_a, snapshot, idx_b)

                intents = evaluate_rules(
                    active_rules, events, _payload_resolver(conn), device.platform
                )
                if suppress_known_good:
                    intents = _drop_known_good_intents(conn, intents)
                if events:
                    append_events(conn, events)
                for intent in intents:
                    ids = [e.id for e in intent.contributing_events if e.id is not None]
                    if len(ids) != len(intent.contributing_events):
                        continue
                    alert = Alert(
                        rule_id=intent.rule_id,
                        device_id=device.id,
                        title=intent.title,
                        detail={"events": ids, "context": intent.context},
                        ts=utcnow_iso(),
                    )
                    insert_alert(conn, alert, ids)
                    alerts.append(alert)

    return SnapshotResult(
        snapshot=snapshot, events=events, prior_snapshot_id=prior_id, alerts=alerts
    )


def _payload_resolver(conn: sqlite3.Connection) -> Any:
    def resolve(event: Event) -> dict[str, Any]:
        hash_ = event.after_hash if event.action != "removed" else event.before_hash
        if hash_ is None:
            return {}
        return load_item_payload(conn, hash_) or {}

    return resolve


def _drop_known_good_intents(
    conn: sqlite3.Connection, intents: list[AlertIntent]
) -> list[AlertIntent]:
    """Drop intents whose every contributing file-event points at a known-good hash.

    Non-file events are never suppressed — the allowlist is a hash concept only.
    A mixed intent survives: the non-file event still tells a story worth alerting on.
    """
    if not intents:
        return intents
    hashes: set[str] = set()
    for intent in intents:
        for e in intent.contributing_events:
            if e.category != "file":
                continue
            candidate = e.after_hash if e.action != "removed" else e.before_hash
            if not candidate:
                continue
            sha = (load_item_payload(conn, candidate) or {}).get("sha256")
            if isinstance(sha, str):
                hashes.add(sha.lower())
    if not hashes:
        return intents

    known = known_good_lookup(conn, hashes)
    if not known:
        return intents

    def all_file_events_known_good(intent: AlertIntent) -> bool:
        file_evs = [e for e in intent.contributing_events if e.category == "file"]
        if not file_evs or len(file_evs) != len(intent.contributing_events):
            return False
        for e in file_evs:
            candidate = e.after_hash if e.action != "removed" else e.before_hash
            if not candidate:
                return False
            sha = (load_item_payload(conn, candidate) or {}).get("sha256")
            if not isinstance(sha, str) or sha.lower() not in known:
                return False
        return True

    return [i for i in intents if not all_file_events_known_good(i)]


def _previous_snapshot_id(
    conn: sqlite3.Connection, device_id: int, current_id: int | None
) -> int | None:
    if current_id is None:
        return None
    row = conn.execute(
        "SELECT id FROM snapshots WHERE device_id = ? AND id < ? "
        "AND kind IN ('baseline','scan','after') "
        "ORDER BY id DESC LIMIT 1",
        (device_id, current_id),
    ).fetchone()
    return int(row["id"]) if row else None
