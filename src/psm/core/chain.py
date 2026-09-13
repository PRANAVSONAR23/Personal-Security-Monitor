"""Append-only event log with SHA-256 hash chain (LLD §6).

Genesis is the empty string. row_hash = sha256(prev_row_hash || canonical_json(core_fields)).
Events within one diff batch are ordered by (category, subject_key) before hashing so the
chain is deterministic across identical inputs.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

from psm.core.models import Event
from psm.normalize.canonical import canonical_json
from psm.store.queries import get_meta, set_meta

GENESIS = ""

_CORE_FIELDS = (
    "device_id",
    "ts",
    "category",
    "action",
    "subject_key",
    "before_hash",
    "after_hash",
    "snap_from",
    "snap_to",
    "severity",
)


def _core_payload(event: Event) -> dict[str, object]:
    return {name: getattr(event, name) for name in _CORE_FIELDS}


def compute_row_hash(prev: str, event: Event) -> str:
    material = prev + canonical_json(_core_payload(event))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _sort_key(e: Event) -> tuple[str, str]:
    return (e.category, e.subject_key)


def append_events(conn: sqlite3.Connection, events: Iterable[Event]) -> list[Event]:
    """Insert events, chaining each row hash. Caller supplies the surrounding transaction."""
    batch = sorted(events, key=_sort_key)
    head = get_meta(conn, "chain_head") or GENESIS
    for event in batch:
        event.prev_row_hash = head
        event.row_hash = compute_row_hash(head, event)
        cur = conn.execute(
            "INSERT INTO events "
            "(device_id, ts, category, action, subject_key, before_hash, after_hash, "
            " snap_from, snap_to, severity, prev_row_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.device_id,
                event.ts,
                event.category,
                event.action,
                event.subject_key,
                event.before_hash,
                event.after_hash,
                event.snap_from,
                event.snap_to,
                event.severity,
                event.prev_row_hash,
                event.row_hash,
            ),
        )
        assert cur.lastrowid is not None
        event.id = cur.lastrowid
        head = event.row_hash
    set_meta(conn, "chain_head", head)
    return batch


@dataclass(slots=True)
class ChainReport:
    ok: bool
    events_checked: int
    head: str
    error: str | None = None
    first_bad_event_id: int | None = None


def verify_chain(conn: sqlite3.Connection) -> ChainReport:
    stored_head = get_meta(conn, "chain_head") or GENESIS
    head = GENESIS
    checked = 0
    rows = conn.execute(
        "SELECT id, device_id, ts, category, action, subject_key, "
        "       before_hash, after_hash, snap_from, snap_to, severity, "
        "       prev_row_hash, row_hash "
        "FROM events ORDER BY id ASC"
    ).fetchall()
    for r in rows:
        checked += 1
        event = Event(
            id=r["id"],
            device_id=r["device_id"],
            ts=r["ts"],
            category=r["category"],
            action=r["action"],
            subject_key=r["subject_key"],
            before_hash=r["before_hash"],
            after_hash=r["after_hash"],
            snap_from=r["snap_from"],
            snap_to=r["snap_to"],
            severity=r["severity"],
        )
        expected = compute_row_hash(head, event)
        if r["prev_row_hash"] != head:
            return ChainReport(
                ok=False,
                events_checked=checked,
                head=stored_head,
                error=f"event {r['id']}: prev_row_hash mismatch",
                first_bad_event_id=r["id"],
            )
        if r["row_hash"] != expected:
            return ChainReport(
                ok=False,
                events_checked=checked,
                head=stored_head,
                error=f"event {r['id']}: row_hash mismatch",
                first_bad_event_id=r["id"],
            )
        head = r["row_hash"]
    if head != stored_head:
        return ChainReport(
            ok=False,
            events_checked=checked,
            head=stored_head,
            error="chain_head in meta does not match tail of events",
        )
    return ChainReport(ok=True, events_checked=checked, head=head)
