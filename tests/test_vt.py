"""VT client tests — network faked with an in-memory opener.

We never make a real HTTP call in the test suite.
"""

from __future__ import annotations

import io
import json
import urllib.error

from psm.enrich.vt import VtClient, VtVerdict


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._stream = io.BytesIO(body)

    def read(self, cap: int | None = None) -> bytes:
        if cap is None:
            return self._body
        return self._stream.read(cap)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class _FakeOpener:
    def __init__(self, table: dict[str, object]) -> None:
        self.table = table
        self.calls: list[str] = []

    def open(self, req, timeout=None):
        self.calls.append(req.full_url)
        payload = self.table.get(req.full_url)
        if isinstance(payload, urllib.error.HTTPError):
            raise payload
        assert isinstance(payload, bytes)
        return _FakeResp(payload)


def _stats_body(stats: dict[str, int]) -> bytes:
    return json.dumps({
        "data": {"attributes": {"last_analysis_stats": stats}}
    }).encode("utf-8")


def test_lookup_parses_malicious_count() -> None:
    sha = "a" * 64
    opener = _FakeOpener({
        f"https://www.virustotal.com/api/v3/files/{sha}": _stats_body(
            {"malicious": 3, "suspicious": 1, "harmless": 0, "undetected": 60}
        ),
    })
    client = VtClient(api_key="test", min_gap_s=0, opener=opener)
    v = client.lookup(sha)
    assert v.known is True
    assert v.malicious == 3
    assert v.suspicious == 1
    assert v.error is None


def test_lookup_404_is_unknown_not_error() -> None:
    sha = "b" * 64
    err = urllib.error.HTTPError(
        url=f"https://vt/{sha}", code=404, msg="Not Found", hdrs=None, fp=None
    )
    opener = _FakeOpener({f"https://www.virustotal.com/api/v3/files/{sha}": err})
    client = VtClient(api_key="test", min_gap_s=0, opener=opener)
    v = client.lookup(sha)
    assert v.known is False
    assert v.error is None


def test_no_api_key_disables_client() -> None:
    client = VtClient(api_key="")
    assert client.enabled is False
    v = client.lookup("c" * 64)
    assert v.error == "no-api-key"


def test_caches_repeat_lookups() -> None:
    sha = "d" * 64
    opener = _FakeOpener({
        f"https://www.virustotal.com/api/v3/files/{sha}": _stats_body({}),
    })
    client = VtClient(api_key="test", min_gap_s=0, opener=opener)
    v1 = client.lookup(sha)
    v2 = client.lookup(sha)
    assert v1 is v2
    assert len(opener.calls) == 1


def test_bulk_lookup_deduplicates() -> None:
    sha = "e" * 64
    opener = _FakeOpener({
        f"https://www.virustotal.com/api/v3/files/{sha}": _stats_body({}),
    })
    client = VtClient(api_key="test", min_gap_s=0, opener=opener)
    result = client.bulk_lookup([sha, sha.upper()])
    assert isinstance(result[sha], VtVerdict)
    assert len(opener.calls) == 1  # dedup by lowercase
