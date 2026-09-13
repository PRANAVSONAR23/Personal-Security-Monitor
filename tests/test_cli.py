from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from psm import __version__
from psm.cli.app import app
from psm.store.db import open_db

runner = CliRunner()


def test_version_flag(tmp_path: Path):
    """v1 shipped a testing doc whose step 3 ran `psm --version`; the flag did not exist."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_db_verify_ok(tmp_path: Path):
    db = tmp_path / "psm.sqlite"
    open_db(db).close()
    result = runner.invoke(app, ["db", "verify", "--db", str(db)])
    assert result.exit_code == 0
    assert "chain ok" in result.stdout


def test_db_verify_detects_tamper(tmp_path: Path):

    db = tmp_path / "psm.sqlite"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO devices (name, platform, identifier, tiers, created_at) "
        "VALUES ('mac','macos','local','[]','2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO events (device_id, ts, source, category, action, subject_key, "
        "prev_row_hash, row_hash) VALUES (1,'2026-01-01T00:00:00Z','inventory','file',"
        "'added','file:/x','','deadbeef')"
    )
    conn.commit()
    conn.close()

    result = runner.invoke(app, ["db", "verify", "--db", str(db)])
    assert result.exit_code == 1
    assert "chain broken" in result.stdout + result.stderr


def test_device_add_requires_identifier_for_android(tmp_path: Path):
    db = tmp_path / "psm.sqlite"
    result = runner.invoke(
        app, ["device", "add", "--name", "phone", "--platform", "android", "--db", str(db)]
    )
    assert result.exit_code == 1


def test_device_add_macos_defaults_to_local(tmp_path: Path):
    db = tmp_path / "psm.sqlite"
    result = runner.invoke(
        app, ["device", "add", "--name", "mac", "--platform", "macos", "--db", str(db)]
    )
    assert result.exit_code == 0
    listed = runner.invoke(app, ["device", "list", "--db", str(db)])
    assert "local" in listed.stdout


def test_windows_platform_is_rejected(tmp_path: Path):
    db = tmp_path / "psm.sqlite"
    result = runner.invoke(
        app, ["device", "add", "--name", "pc", "--platform", "windows", "--db", str(db)]
    )
    assert result.exit_code == 1
