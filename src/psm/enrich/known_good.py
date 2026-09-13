"""known_good_hashes: user-supplied allowlists + baseline capture (LLD §Phase 6).

Two import formats accepted:
  1. One sha256 (64 hex chars) per line — nothing else. `source` defaults to the file's stem.
  2. JSONL: `{"sha256": "...", "source": "...", "label": "..."}` per line.

Baseline capture walks the current file-category items in the DB and drops their
hashes into `known_good_hashes` with `source="baseline:<host>:<ts>"`. Handy on a
freshly-installed OS.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(slots=True)
class KnownGoodEntry:
    sha256: str
    source: str
    label: str | None = None


class KnownGoodParseError(ValueError):
    pass


def parse_file(path: Path, default_source: str | None = None) -> list[KnownGoodEntry]:
    """Read a plain-text-per-line OR JSONL file. Raises on unknown line formats."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return list(parse_lines(text.splitlines(), default_source or path.stem))


def parse_lines(
    lines: Iterable[str], default_source: str
) -> Iterable[KnownGoodEntry]:
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise KnownGoodParseError(f"line {lineno}: invalid JSON: {e}") from e
            if not isinstance(obj, dict) or "sha256" not in obj:
                raise KnownGoodParseError(
                    f"line {lineno}: JSONL entry must include sha256"
                )
            sha = str(obj["sha256"]).lower()
            if not _SHA256_RE.match(sha):
                raise KnownGoodParseError(f"line {lineno}: invalid sha256 {sha!r}")
            yield KnownGoodEntry(
                sha256=sha,
                source=str(obj.get("source", default_source)),
                label=str(obj["label"]) if obj.get("label") is not None else None,
            )
            continue

        if not _SHA256_RE.match(line):
            raise KnownGoodParseError(
                f"line {lineno}: expected sha256 or JSONL, got {line!r}"
            )
        yield KnownGoodEntry(sha256=line.lower(), source=default_source)


def import_entries(
    conn: sqlite3.Connection, entries: Iterable[KnownGoodEntry]
) -> int:
    """Upsert entries. Returns count inserted+updated. Runs in one implicit transaction."""
    payload = [(e.sha256, e.source, e.label) for e in entries]
    if not payload:
        return 0
    conn.executemany(
        "INSERT INTO known_good_hashes (sha256, source, label) VALUES (?, ?, ?) "
        "ON CONFLICT(sha256) DO UPDATE SET source = excluded.source, "
        "label = excluded.label",
        payload,
    )
    conn.commit()
    return len(payload)


def capture_baseline(
    conn: sqlite3.Connection, source: str, *, device_id: int | None = None
) -> int:
    """Snapshot every currently-known file sha256 into known_good_hashes.

    Scopes to a specific device when given (baseline the fresh OS); otherwise reads
    every file-category item in the store. Returns count captured.
    """
    if device_id is None:
        rows = conn.execute(
            "SELECT DISTINCT json_extract(payload, '$.sha256') AS sha "
            "FROM items WHERE category = 'file'"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT DISTINCT json_extract(i.payload, '$.sha256') AS sha "
            "FROM items i JOIN snapshot_items si ON si.item_hash = i.hash "
            "JOIN snapshots s ON s.id = si.snapshot_id "
            "WHERE i.category = 'file' AND s.device_id = ?",
            (device_id,),
        ).fetchall()

    entries = [
        KnownGoodEntry(sha256=row["sha"].lower(), source=source)
        for row in rows
        if row["sha"] and _SHA256_RE.match(row["sha"])
    ]
    return import_entries(conn, entries)


def lookup(conn: sqlite3.Connection, sha256: str) -> KnownGoodEntry | None:
    row = conn.execute(
        "SELECT sha256, source, label FROM known_good_hashes WHERE sha256 = ?",
        (sha256.lower(),),
    ).fetchone()
    if row is None:
        return None
    return KnownGoodEntry(sha256=row["sha256"], source=row["source"], label=row["label"])


def bulk_lookup(
    conn: sqlite3.Connection, hashes: Iterable[str]
) -> dict[str, KnownGoodEntry]:
    """Return {sha256: KnownGoodEntry} for the hashes present. Missing keys are absent."""
    unique = list({h.lower() for h in hashes if h})
    if not unique:
        return {}
    placeholders = ",".join("?" * len(unique))
    rows = conn.execute(
        f"SELECT sha256, source, label FROM known_good_hashes "
        f"WHERE sha256 IN ({placeholders})",
        tuple(unique),
    ).fetchall()
    return {
        r["sha256"]: KnownGoodEntry(
            sha256=r["sha256"], source=r["source"], label=r["label"]
        )
        for r in rows
    }
