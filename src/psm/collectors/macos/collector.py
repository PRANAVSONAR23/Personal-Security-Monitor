"""macOS collector — shim-driven, invoked via SSH or an already-collected file.

The collector never runs shim code inside the controller process; it either pipes
the shim over SSH (`ssh_target` set) or reads a pre-collected envelope from disk
(`envelope_path` set).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from psm.collectors.base import Collector, RawBundle
from psm.collectors.macos import ingest, transport
from psm.core.models import CollectionGap, Device


@dataclass(slots=True)
class MacosConfig:
    ssh_target: str | None = None
    envelope_path: Path | None = None
    envelope_bytes: bytes | None = None       # for tests: bypass filesystem + ssh
    shim_path: Path | None = None
    modules: tuple[str, ...] = (
        "apps",
        "persistence",
        "permissions",
    )
    file_walk: tuple[str, ...] = ()
    max_file_mb: int = 200
    timeout_s: int = 300


class MacosCollector(Collector):
    platform = "macos"
    # Category-level capabilities, matching what the normalizer emits.
    ALL_MODULES: tuple[str, ...] = (
        "application", "persistence", "permission", "file", "browser",
    )

    def __init__(self, config: MacosConfig | None = None) -> None:
        self.config = config or MacosConfig()

    def capabilities(self, device: Device) -> set[str]:
        cfg = self.config
        if cfg.envelope_bytes is not None or cfg.envelope_path is not None:
            return set(self.ALL_MODULES)
        if cfg.ssh_target:
            return set(self.ALL_MODULES)
        return set()

    def collect(
        self,
        device: Device,
        modules: set[str],
        timeout_s: int = 300,
    ) -> RawBundle:
        cfg = self.config
        if cfg.envelope_bytes is not None:
            env = ingest.parse_envelope(cfg.envelope_bytes)
            return ingest.envelope_to_bundle(device, env)

        if cfg.envelope_path is not None:
            return ingest.parse_file(device, str(cfg.envelope_path))

        if not cfg.ssh_target:
            return RawBundle(
                device=device,
                gaps=[CollectionGap("device", "no-transport",
                                    "MacosConfig needs ssh_target or envelope_path")],
            )

        shim_path = cfg.shim_path or transport.default_shim_path()
        shim_modules = _to_shim_modules(modules, self.ALL_MODULES)
        try:
            result = transport.run_shim(
                cfg.ssh_target,
                shim_path,
                modules=shim_modules,
                file_walk=cfg.file_walk,
                max_file_mb=cfg.max_file_mb,
                timeout_s=cfg.timeout_s,
            )
        except transport.SshError as e:
            return RawBundle(
                device=device,
                gaps=[CollectionGap("device", "ssh-failed", str(e))],
            )
        env = ingest.parse_envelope(result.stdout)
        return ingest.envelope_to_bundle(device, env)


def _to_shim_modules(
    categories: set[str], all_categories: tuple[str, ...]
) -> tuple[str, ...]:
    """Category → shim module name. Preserves ALL_MODULES ordering for determinism."""
    inverse = {
        "application": "apps",
        "persistence": "persistence",
        "permission": "permissions",
        "file": "files",
        "browser": "browser",
    }
    selected = [
        inverse[c] for c in all_categories if c in categories and c in inverse
    ]
    return tuple(selected)
