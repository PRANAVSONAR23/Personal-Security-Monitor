"""VirusTotal enrichment — hash-only, opt-in (LLD §Phase 6).

We NEVER upload file content. We only query `GET /api/v3/files/{sha256}` — a
lookup by hash. If VT has never seen the file the API returns 404 → we treat
that as `unknown`, not an error.

Rate limits: VT public API is 4 requests/minute. We serialize requests with a
minimum inter-call gap and cache responses in a small dict for the lifetime of
the scan. No caching to disk in v1 — the DB is not the right home for third-party
verdicts we can't verify.

Requires `PSM_VT_API_KEY` in the environment (or an explicit key passed by the
caller). Missing key → the enrichment is skipped with a gap-style note.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field

VT_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"
DEFAULT_TIMEOUT_S = 15.0
MIN_GAP_S = 15.5  # 4 req/min public limit → wait a hair over 15s between calls
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # VT file-info responses are tiny — cap defensively


@dataclass(slots=True)
class VtVerdict:
    sha256: str
    known: bool  # False → VT has never seen this hash (404)
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    error: str | None = None
    raw: dict[str, object] = field(default_factory=dict)


class VtClient:
    """Serial VT lookup client with per-instance rate-limiting and in-memory cache."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        min_gap_s: float = MIN_GAP_S,
        opener: object | None = None,  # tests inject a urllib.request.OpenerDirector-like
    ) -> None:
        self.api_key = api_key or os.environ.get("PSM_VT_API_KEY", "")
        self.timeout_s = timeout_s
        self.min_gap_s = min_gap_s
        self._last_call_at: float = 0.0
        self._cache: dict[str, VtVerdict] = {}
        self._opener = opener

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup(self, sha256: str) -> VtVerdict:
        sha = sha256.lower()
        if sha in self._cache:
            return self._cache[sha]
        if not self.enabled:
            return VtVerdict(sha256=sha, known=False, error="no-api-key")

        self._rate_limit()
        try:
            data = self._get_json(VT_ENDPOINT.format(sha256=sha))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                verdict = VtVerdict(sha256=sha, known=False)
            else:
                verdict = VtVerdict(sha256=sha, known=False, error=f"http-{e.code}")
        except urllib.error.URLError as e:
            verdict = VtVerdict(sha256=sha, known=False, error=f"url-error: {e.reason}")
        except (TimeoutError, OSError) as e:
            verdict = VtVerdict(sha256=sha, known=False, error=f"io-error: {e}")
        else:
            verdict = _parse_verdict(sha, data)

        self._cache[sha] = verdict
        return verdict

    def bulk_lookup(self, hashes: Iterable[str]) -> dict[str, VtVerdict]:
        """Serial iteration. Callers who need parallelism should thread themselves;
        the public API rate limit makes it moot anyway."""
        out: dict[str, VtVerdict] = {}
        for h in {h.lower() for h in hashes if h}:
            out[h] = self.lookup(h)
        return out

    def _rate_limit(self) -> None:
        now = time.monotonic()
        wait = self.min_gap_s - (now - self._last_call_at)
        if wait > 0:
            time.sleep(wait)
        self._last_call_at = time.monotonic()

    def _get_json(self, url: str) -> dict[str, object]:
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "psm/enrich",
            },
        )
        opener = self._opener or urllib.request.build_opener()
        assert hasattr(opener, "open")
        with opener.open(req, timeout=self.timeout_s) as resp:
            body = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"VT response exceeded {MAX_RESPONSE_BYTES} bytes")
        obj = json.loads(body)
        if not isinstance(obj, dict):
            raise ValueError(f"unexpected VT payload type: {type(obj).__name__}")
        return obj


def _parse_verdict(sha: str, data: dict[str, object]) -> VtVerdict:
    attrs = _dig(data, "data", "attributes")
    stats = _dig(attrs, "last_analysis_stats") if isinstance(attrs, dict) else None
    if not isinstance(stats, dict):
        return VtVerdict(sha256=sha, known=True, raw=data)
    return VtVerdict(
        sha256=sha,
        known=True,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        raw=data,
    )


def _dig(root: object, *path: str) -> object:
    cur: object = root
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur
