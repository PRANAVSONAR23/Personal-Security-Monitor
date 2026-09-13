from __future__ import annotations

import time
from pathlib import Path

from psm.collectors.windows.modules import files


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_walk_produces_entries(tmp_path: Path):
    _write(tmp_path / "a.txt", b"hello")
    _write(tmp_path / "sub" / "b.bin", b"\x00\x01\x02")
    result = files.collect([tmp_path])
    subjects = sorted(e["path"] for e in result.entries)
    assert len(subjects) == 2
    for e in result.entries:
        assert e["sha256"] and len(e["sha256"]) == 64
        assert e["size"] > 0


def test_missing_root_records_gap(tmp_path: Path):
    result = files.collect([tmp_path / "does-not-exist"])
    assert result.entries == []
    assert any(g.reason == "path-missing" for g in result.gaps)


def test_size_cap_skips_and_records_null_hash(tmp_path: Path):
    big = tmp_path / "big.bin"
    _write(big, b"x" * 3000)
    result = files.collect([tmp_path], max_file_mb=0)  # 0 MB cap forces skip
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry["sha256"] is None
    assert entry["skipped"] == "size"


def test_skip_cache_reuses_hash_when_stat_matches(tmp_path: Path):
    p = tmp_path / "a.bin"
    _write(p, b"payload")

    first = files.collect([tmp_path])
    (path_norm, entry) = next(iter(first.cache.items()))
    real_hash = first.entries[0]["sha256"]
    size, mtime_ns, file_id, _ = entry

    # Inject a fake hash into the prior cache with the exact same stat triple.
    # If the module honors the skip cache, it must return this fake hash without
    # re-hashing the file (which would yield the real hash).
    fake_prior = {path_norm: (size, mtime_ns, file_id, "deadbeef")}
    second = files.collect([tmp_path], prior_cache=fake_prior)
    assert second.entries[0]["sha256"] == "deadbeef"
    assert second.entries[0]["sha256"] != real_hash


def test_modified_file_gets_rehashed(tmp_path: Path):
    p = tmp_path / "a.bin"
    _write(p, b"payload")
    first = files.collect([tmp_path])
    original_hash = first.entries[0]["sha256"]

    time.sleep(0.01)
    p.write_bytes(b"payload-and-more")  # changed size, and mtime advances

    second = files.collect([tmp_path], prior_cache=first.cache)
    assert second.entries[0]["sha256"] != original_hash
