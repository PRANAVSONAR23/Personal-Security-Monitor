"""Canonical JSON — frozen spec, do not change without bumping schema_version."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalJSONError(ValueError):
    pass


def _check(obj: Any) -> None:
    if isinstance(obj, bool) or obj is None or isinstance(obj, int | str):
        return
    if isinstance(obj, float):
        raise CanonicalJSONError(
            "floats are forbidden in canonical payloads; stringify before hashing"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalJSONError(f"dict keys must be str, got {type(k).__name__}")
            _check(v)
        return
    if isinstance(obj, list | tuple):
        for v in obj:
            _check(v)
        return
    raise CanonicalJSONError(f"unsupported type in canonical payload: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def item_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
