"""SQLite connection + migration runner. WAL, foreign keys always on."""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_MIGRATION_RE = re.compile(r"^(\d{3})_[a-z0-9_]+\.sql$")

PSM_MAJOR = "2"


def default_data_dir() -> Path:
    root = os.environ.get("PSM_DATA_DIR")
    if root:
        return Path(root)
    return Path.home() / "Library" / "Application Support" / "psm"


def default_db_path() -> Path:
    return default_data_dir() / "psm.sqlite"


def connect(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def _discover_migrations() -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for p in sorted(MIGRATIONS_DIR.iterdir()):
        m = _MIGRATION_RE.match(p.name)
        if m:
            found.append((int(m.group(1)), p))
    return found


def current_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if row is None:
        return 0
    r = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    return int(r["value"]) if r else 0


def migrate(conn: sqlite3.Connection) -> int:
    current = current_schema_version(conn)
    applied = 0
    for version, path in _discover_migrations():
        if version <= current:
            continue
        sql = path.read_text(encoding="utf-8")
        # executescript issues its own COMMIT, so we can't wrap it in our transaction().
        # Fresh-DB migrations are self-contained (schema + meta seed in the same script),
        # so partial failure leaves an unusable file that the next run recreates.
        conn.executescript(sql)
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )
        applied += 1
    return applied


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


class IncompatibleDatabase(RuntimeError):
    pass


def _assert_not_v1(conn: sqlite3.Connection, path: Path) -> None:
    """v2 changed canonical JSON and path normalization, invalidating every v1
    item hash and the entire event chain. There is no meaningful migration, so
    say so plainly instead of silently producing a corrupt diff."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if row is None:
        return
    r = conn.execute("SELECT value FROM meta WHERE key='psm_major'").fetchone()
    if r is not None and r["value"] == PSM_MAJOR:
        return
    has_events = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    ).fetchone()
    if has_events is None:
        return
    raise IncompatibleDatabase(
        f"{path} is a psm v1 database. v2 changed canonical JSON (v1→v2) and path "
        f"normalization, so every stored item hash and the whole event chain are "
        f"invalid under v2 rules — there is no migration. Move it aside and take a "
        f"fresh baseline:  mv {path} {path}.v1"
    )


def open_db(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path or default_db_path())
    conn = connect(path)
    _assert_not_v1(conn, path)
    migrate(conn)
    return conn
