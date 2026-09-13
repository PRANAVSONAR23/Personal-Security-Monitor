"""Unit tests for known_good parser + lookup helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from psm.enrich import known_good

VALID_SHA = "a" * 64


def test_parse_plain_sha_lines(tmp_path: Path) -> None:
    p = tmp_path / "list.txt"
    p.write_text(
        f"# comment\n{VALID_SHA}\n{VALID_SHA.upper()}\n\n{'b' * 64}\n",
        encoding="utf-8",
    )
    entries = known_good.parse_file(p)
    shas = [e.sha256 for e in entries]
    assert shas == [VALID_SHA, VALID_SHA, "b" * 64]
    assert all(e.source == "list" for e in entries)


def test_parse_jsonl_source_and_label(tmp_path: Path) -> None:
    p = tmp_path / "list.jsonl"
    p.write_text(
        '{"sha256": "' + VALID_SHA + '", "source": "vendor-A", "label": "clean"}\n',
        encoding="utf-8",
    )
    entries = known_good.parse_file(p)
    assert len(entries) == 1
    assert entries[0].source == "vendor-A"
    assert entries[0].label == "clean"


def test_parse_rejects_bad_sha(tmp_path: Path) -> None:
    p = tmp_path / "list.txt"
    p.write_text("not-a-hash\n", encoding="utf-8")
    with pytest.raises(known_good.KnownGoodParseError):
        known_good.parse_file(p)


def test_import_and_lookup_roundtrip(db) -> None:
    n = known_good.import_entries(
        db, [known_good.KnownGoodEntry(sha256=VALID_SHA, source="unit")]
    )
    assert n == 1
    hit = known_good.lookup(db, VALID_SHA)
    assert hit is not None
    assert hit.source == "unit"

    # Bulk lookup returns a dict keyed by sha.
    bulk = known_good.bulk_lookup(db, [VALID_SHA, "c" * 64])
    assert VALID_SHA in bulk
    assert "c" * 64 not in bulk


def test_import_upserts(db) -> None:
    known_good.import_entries(
        db, [known_good.KnownGoodEntry(sha256=VALID_SHA, source="v1")]
    )
    known_good.import_entries(
        db, [known_good.KnownGoodEntry(sha256=VALID_SHA, source="v2", label="upgraded")]
    )
    hit = known_good.lookup(db, VALID_SHA)
    assert hit is not None
    assert hit.source == "v2"
    assert hit.label == "upgraded"
