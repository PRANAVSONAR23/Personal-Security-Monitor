"""Orchestrator — device resolution, snapshot lifecycle, diff wiring."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from psm import __version__
from psm.collectors.android.collector import AndroidCollector, AndroidConfig
from psm.collectors.base import Collector, Normalizer
from psm.collectors.macos.collector import MacosCollector, MacosConfig
from psm.collectors.windows.collector import WindowsCollector, WindowsConfig
from psm.collectors.windows.modules.files import CacheMap
from psm.core.chain import append_events
from psm.core.diff import diff
from psm.core.models import Alert, Device, Event, Snapshot, utcnow_iso
from psm.core.rules import AlertIntent, Rule, load_builtin_rules
from psm.core.rules import evaluate as evaluate_rules
from psm.enrich.known_good import bulk_lookup as known_good_lookup
from psm.normalize.android import AndroidNormalizer
from psm.normalize.macos import MacosNormalizer
from psm.normalize.windows import WindowsNormalizer
from psm.store.db import transaction
from psm.store.queries import (
    insert_alert,
    insert_snapshot,
    load_file_hash_cache,
    load_item_payload,
    load_snapshot,
    load_snapshot_index,
    save_file_hash_cache,
)


class OrchestratorError(RuntimeError):
    pass


@dataclass(slots=True)
class SnapshotResult:
    snapshot: Snapshot
    events: list[Event]
    prior_snapshot_id: int | None
    alerts: list[Alert] = field(default_factory=list)


def _select_collector_and_normalizer(
    device: Device,
    file_walk_paths: tuple[str, ...],
    prior_cache: CacheMap,
    android_config: AndroidConfig | None = None,
    macos_config: MacosConfig | None = None,
    windows_config: WindowsConfig | None = None,
) -> tuple[Collector, Normalizer, WindowsConfig | None]:
    if device.platform == "windows":
        cfg = windows_config or WindowsConfig()
        cfg.file_walk_paths = cfg.file_walk_paths or file_walk_paths
        cfg.prior_file_cache = cfg.prior_file_cache or prior_cache
        return WindowsCollector(cfg), WindowsNormalizer(), cfg
    if device.platform == "android":
        return AndroidCollector(android_config or AndroidConfig()), AndroidNormalizer(), None
    if device.platform == "macos":
        return MacosCollector(macos_config or MacosConfig()), MacosNormalizer(), None
    raise OrchestratorError(f"platform not implemented: {device.platform}")


def take_snapshot(
    conn: sqlite3.Connection,
    device: Device,
    *,
    kind: str,
    file_walk_paths: tuple[str, ...] = (),
    modules: set[str] | None = None,
    rules: list[Rule] | None = None,
    android_config: AndroidConfig | None = None,
    macos_config: MacosConfig | None = None,
    windows_config: WindowsConfig | None = None,
    suppress_known_good: bool = False,
) -> SnapshotResult:
    """Collect + normalize + persist. For 'scan' kinds, also diff, evaluate rules, alert."""
    if device.id is None:
        raise OrchestratorError("device must be persisted before taking a snapshot")

    prior_cache = load_file_hash_cache(conn, device.id) if file_walk_paths else {}
    collector, normalizer, cfg = _select_collector_and_normalizer(
        device, file_walk_paths, prior_cache, android_config, macos_config, windows_config
    )

    caps = collector.capabilities(device)
    target = (modules or caps) & caps
    bundle = collector.collect(device, target)
    items = normalizer.normalize(bundle)

    snapshot = Snapshot(
        device_id=device.id,
        kind=kind,  # type: ignore[arg-type]
        capabilities=target,
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
        if cfg is not None and cfg.new_file_cache is not None:
            save_file_hash_cache(conn, device.id, cfg.new_file_cache)

        if kind != "baseline":
            prior_id = _previous_snapshot_id(conn, device.id, snapshot.id)
            if prior_id is not None:
                prior_snap = load_snapshot(conn, prior_id)
                idx_a = load_snapshot_index(conn, prior_id)
                assert snapshot.id is not None
                idx_b = load_snapshot_index(conn, snapshot.id)
                events = diff(prior_snap, idx_a, snapshot, idx_b)

                alert_intents = evaluate_rules(
                    active_rules, events, _payload_resolver(conn)
                )
                if suppress_known_good:
                    alert_intents = _drop_known_good_intents(conn, alert_intents)
                if events:
                    append_events(conn, events)  # events now carry rule-upgraded severity
                for intent in alert_intents:
                    contributing_ids = [
                        e.id for e in intent.contributing_events if e.id is not None
                    ]
                    if len(contributing_ids) != len(intent.contributing_events):
                        continue
                    alert = Alert(
                        rule_id=intent.rule_id,
                        device_id=device.id,
                        title=intent.title,
                        detail={
                            "events": contributing_ids,
                            "context": intent.context,
                        },
                        ts=utcnow_iso(),
                    )
                    insert_alert(conn, alert, contributing_ids)
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
    An intent with a mix of file + non-file events isn't suppressed either: the
    non-file event still tells a story worth alerting on.
    """
    if not intents:
        return intents
    hashes: set[str] = set()
    file_events = [
        e
        for intent in intents
        for e in intent.contributing_events
        if e.category == "file"
    ]
    for e in file_events:
        candidate = e.after_hash if e.action != "removed" else e.before_hash
        if not candidate:
            continue
        payload = load_item_payload(conn, candidate) or {}
        sha = payload.get("sha256")
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
            payload = load_item_payload(conn, candidate) or {}
            sha = payload.get("sha256")
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
