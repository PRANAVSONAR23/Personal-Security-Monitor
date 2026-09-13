"""Ingest a macOS shim envelope into a RawBundle.

Per LLD §3.8: schema-validate first, reject unknown module names, drop unknown
payload fields. The validator is hand-rolled and covers only the subset we care
about (envelope shape + required per-item fields) — a full jsonschema engine
would be an unnecessary dependency.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from psm.collectors.base import RawBundle
from psm.core.models import CollectionGap, Device

SUPPORTED_VERSIONS = frozenset({"1.0"})
MAX_ENVELOPE_BYTES = 128 * 1024 * 1024  # matches the SSH transport output cap

# Category name mapping: shim's `modules.apps` → inventory category `application`, etc.
_MODULE_TO_CATEGORY: dict[str, str] = {
    "apps": "application",
    "persistence": "persistence",
    "permissions": "permission",
    "files": "file",
    "processes": "process",
    "network": "network",
    "browser": "browser",
}

# Per-module allowed payload keys. Unknown keys are silently dropped (LLD §3.8).
_ALLOWED_FIELDS: dict[str, tuple[str, ...]] = {
    "apps": ("id", "name", "version", "path", "source"),
    "persistence": (
        "location", "name", "path", "target", "args", "run_at_load", "enabled",
    ),
    "permissions": ("pkg", "permission", "granted", "scope"),
    "files": (
        "path", "size", "mtime", "sha256", "executable", "signature_status", "skipped",
    ),
    "processes": ("pid", "ppid", "uid", "started", "command"),
    "network": ("proto", "addr", "port", "process", "pid_seen"),
    "browser": (
        "browser", "profile", "id", "name", "version", "permissions",
        "install_time", "enabled",
    ),
}

_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "apps": ("id", "name", "path"),
    "persistence": ("location", "name", "path"),
    "permissions": ("pkg", "permission", "granted"),
    "files": ("path", "size", "mtime"),
    "processes": (),
    "network": (),
    "browser": ("browser", "id", "name"),
}

_VERSION_RE = re.compile(r"^\d+\.\d+$")


class ShimValidationError(ValueError):
    pass


@dataclass(slots=True)
class ShimEnvelope:
    host: str
    taken_at: str
    version: str
    modules: dict[str, list[dict[str, Any]]]
    gaps: list[dict[str, Any]]


def parse_envelope(raw: str | bytes) -> ShimEnvelope:  # noqa: PLR0912
    """Load, validate, and normalize a shim envelope. Raises ShimValidationError."""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ShimValidationError(f"invalid JSON: {e}") from e

    if not isinstance(payload, dict):
        raise ShimValidationError("envelope must be a JSON object")

    if payload.get("psm_collector") != "macos":
        raise ShimValidationError(
            f"unexpected psm_collector: {payload.get('psm_collector')!r}"
        )

    version = payload.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise ShimValidationError(f"invalid version: {version!r}")
    if version not in SUPPORTED_VERSIONS:
        raise ShimValidationError(
            f"unsupported shim version {version!r} (supported: {sorted(SUPPORTED_VERSIONS)})"
        )

    host = payload.get("host")
    if not isinstance(host, str) or not host:
        raise ShimValidationError("host missing or empty")

    taken_at = payload.get("taken_at")
    if not isinstance(taken_at, str) or not taken_at:
        raise ShimValidationError("taken_at missing or empty")

    modules_raw = payload.get("modules")
    if not isinstance(modules_raw, dict):
        raise ShimValidationError("modules must be an object")

    modules: dict[str, list[dict[str, Any]]] = {}
    for name, items in modules_raw.items():
        if name not in _MODULE_TO_CATEGORY:
            raise ShimValidationError(f"unknown module {name!r}")
        if not isinstance(items, list):
            raise ShimValidationError(f"module {name!r} must be a list")
        modules[name] = [_scrub_item(name, item) for item in items]

    gaps_raw = payload.get("gaps", [])
    if not isinstance(gaps_raw, list):
        raise ShimValidationError("gaps must be a list")
    gaps: list[dict[str, Any]] = []
    for gap in gaps_raw:
        if not isinstance(gap, dict) or "module" not in gap or "reason" not in gap:
            raise ShimValidationError(f"invalid gap: {gap!r}")
        gaps.append({
            "module": str(gap["module"]),
            "reason": str(gap["reason"]),
            "detail": str(gap.get("detail", "")),
        })

    return ShimEnvelope(
        host=host, taken_at=taken_at, version=version, modules=modules, gaps=gaps
    )


def _scrub_item(module: str, item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ShimValidationError(f"module {module!r} item is not an object: {item!r}")
    allowed = _ALLOWED_FIELDS[module]
    required = _REQUIRED_FIELDS[module]
    missing = [k for k in required if k not in item]
    if missing:
        raise ShimValidationError(
            f"module {module!r} item missing required field(s) {missing}: {item!r}"
        )
    return {k: item[k] for k in allowed if k in item}


def envelope_to_bundle(device: Device, env: ShimEnvelope) -> RawBundle:
    """Materialize a RawBundle from a validated envelope.

    Module names are translated to inventory *category* names so downstream code
    (diff, rules) sees the same keys the Windows/Android collectors produce.
    """
    raw: dict[str, Any] = {}
    for module_name, items in env.modules.items():
        category = _MODULE_TO_CATEGORY[module_name]
        raw[category] = list(items)

    bundle_gaps = [
        CollectionGap(module=g["module"], reason=g["reason"], detail=g["detail"])
        for g in env.gaps
    ]
    return RawBundle(device=device, taken_at=env.taken_at, raw=raw, gaps=bundle_gaps)


def parse_file(device: Device, path: str) -> RawBundle:
    with open(path, "rb") as f:
        data = f.read(MAX_ENVELOPE_BYTES + 1)
    if len(data) > MAX_ENVELOPE_BYTES:
        raise ShimValidationError(
            f"envelope exceeded {MAX_ENVELOPE_BYTES} bytes; refusing to parse"
        )
    env = parse_envelope(data)
    return envelope_to_bundle(device, env)
