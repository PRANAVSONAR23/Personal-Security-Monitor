from __future__ import annotations

from psm.core.chain import GENESIS, append_events, compute_row_hash, verify_chain
from psm.core.models import Device, Event, Snapshot
from psm.store.db import transaction
from psm.store.queries import get_meta, insert_device, insert_snapshot


def _seed(db) -> tuple[Device, Snapshot, Snapshot]:
    d = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, d)
    assert d.id is not None
    a = Snapshot(device_id=d.id, kind="baseline", capabilities={"file"}, tool_version="0.1.0")
    b = Snapshot(device_id=d.id, kind="scan", capabilities={"file"}, tool_version="0.1.0")
    insert_snapshot(db, a, [])
    insert_snapshot(db, b, [])
    return d, a, b


def _event(
    device_id: int, snap_from: int, snap_to: int, subject: str, action: str = "added"
) -> Event:
    return Event(
        device_id=device_id,
        ts="2026-07-05T12:00:00Z",
        category="file",
        action=action,  # type: ignore[arg-type]
        subject_key=subject,
        before_hash=None,
        after_hash=None,
        snap_from=snap_from,
        snap_to=snap_to,
    )


def test_first_event_uses_genesis(db):
    d, a, b = _seed(db)
    ev = _event(d.id, a.id, b.id, "file:x")
    with transaction(db):
        append_events(db, [ev])
    assert ev.prev_row_hash == GENESIS
    assert ev.row_hash == compute_row_hash(GENESIS, ev)
    assert get_meta(db, "chain_head") == ev.row_hash


def test_chain_links_across_batches(db):
    d, a, b = _seed(db)
    with transaction(db):
        append_events(db, [_event(d.id, a.id, b.id, "file:one")])
    with transaction(db):
        append_events(db, [_event(d.id, a.id, b.id, "file:two")])
    report = verify_chain(db)
    assert report.ok, report.error
    assert report.events_checked == 2


def test_verify_ok_on_empty_db(db):
    report = verify_chain(db)
    assert report.ok
    assert report.events_checked == 0
    assert report.head == GENESIS


def test_batch_sorted_deterministically(db):
    d, a, b = _seed(db)
    with transaction(db):
        append_events(
            db,
            [
                _event(d.id, a.id, b.id, "file:zzz"),
                _event(d.id, a.id, b.id, "file:aaa"),
                _event(d.id, a.id, b.id, "file:mmm"),
            ],
        )
    subjects = [
        r["subject_key"]
        for r in db.execute("SELECT subject_key FROM events ORDER BY id").fetchall()
    ]
    assert subjects == ["file:aaa", "file:mmm", "file:zzz"]


def test_tampered_payload_detected(db):
    d, a, b = _seed(db)
    with transaction(db):
        append_events(db, [_event(d.id, a.id, b.id, "file:x")])
    db.execute("UPDATE events SET subject_key = 'file:tampered' WHERE id = 1")
    report = verify_chain(db)
    assert not report.ok
    assert report.first_bad_event_id == 1


def test_tampered_head_detected(db):
    d, a, b = _seed(db)
    with transaction(db):
        append_events(db, [_event(d.id, a.id, b.id, "file:x")])
    db.execute("UPDATE meta SET value = 'deadbeef' WHERE key = 'chain_head'")
    report = verify_chain(db)
    assert not report.ok
    assert "chain_head" in (report.error or "")


def test_deleted_tail_event_detected(db):
    d, a, b = _seed(db)
    with transaction(db):
        append_events(
            db,
            [
                _event(d.id, a.id, b.id, "file:one"),
                _event(d.id, a.id, b.id, "file:two"),
            ],
        )
    db.execute("DELETE FROM events WHERE subject_key = 'file:two'")
    report = verify_chain(db)
    assert not report.ok
