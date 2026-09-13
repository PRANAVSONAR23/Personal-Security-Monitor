from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from psm.cli.app import app
from psm.core.chain import append_events
from psm.core.models import Device, Event, Snapshot
from psm.store.db import open_db, transaction
from psm.store.queries import insert_device, insert_snapshot

runner = CliRunner()


def _seed_valid_chain(db_path: Path) -> None:
    conn = open_db(db_path)
    try:
        d = Device(name="pc", platform="windows", identifier="localhost")
        insert_device(conn, d)
        assert d.id is not None
        snap = Snapshot(device_id=d.id, kind="scan", capabilities={"file"}, tool_version="0.1.0")
        insert_snapshot(conn, snap, [])
        with transaction(conn):
            append_events(
                conn,
                [
                    Event(
                        device_id=d.id,
                        ts="2026-07-05T12:00:00Z",
                        category="file",
                        action="added",
                        subject_key="file:x",
                        after_hash=None,
                        snap_to=snap.id,  # type: ignore[arg-type]
                    )
                ],
            )
    finally:
        conn.close()


def test_db_verify_ok(tmp_path: Path):
    db_path = tmp_path / "psm.sqlite"
    _seed_valid_chain(db_path)
    result = runner.invoke(app, ["db", "verify", "--db", str(db_path)])
    assert result.exit_code == 0, result.output
    assert "chain ok" in result.output


def test_db_verify_detects_tamper(tmp_path: Path):
    db_path = tmp_path / "psm.sqlite"
    _seed_valid_chain(db_path)
    conn = open_db(db_path)
    try:
        conn.execute("UPDATE events SET subject_key = 'file:tampered' WHERE id = 1")
    finally:
        conn.close()
    result = runner.invoke(app, ["db", "verify", "--db", str(db_path)])
    assert result.exit_code == 1
