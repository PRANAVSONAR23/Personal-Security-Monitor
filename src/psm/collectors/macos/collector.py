"""macOS collector — in-process. The Mac is both controller and target, so there
is no transport layer here at all.

Capability planning is tier-driven: `permissions` and `browser` need Full Disk
Access, and login items need root. What lands in the snapshot is
`RawBundle.collected` — what actually produced output (F1).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from psm.collectors.base import Collector, FileCache, ModuleResult, RawBundle
from psm.collectors.macos.modules import apps, browser, files, launchd, tcc
from psm.core.models import Device

DEFAULT_WALK: tuple[str, ...] = (
    "~/Downloads",
    "~/Library/LaunchAgents",
    "/usr/local/bin",
    "/opt/homebrew/bin",
)


@dataclass(slots=True)
class MacosConfig:
    file_walk_paths: tuple[str, ...] = DEFAULT_WALK
    max_file_mb: int = files.DEFAULT_MAX_FILE_MB
    include_system_launchd: bool = True
    check_signatures: bool = True
    prior_file_cache: FileCache = field(default_factory=dict)
    new_file_cache: FileCache = field(default_factory=dict)


class MacosCollector(Collector):
    platform = "macos"
    ALL_MODULES: tuple[str, ...] = (
        "application",
        "persistence",
        "permission",
        "file",
        "browser",
    )

    def __init__(self, config: MacosConfig | None = None) -> None:
        self.config = config or MacosConfig()

    # -- FileCacheAware --------------------------------------------------

    def load_file_cache(self, cache: FileCache) -> None:
        self.config.prior_file_cache = cache

    def dump_file_cache(self) -> FileCache:
        return self.config.new_file_cache

    # -- Collector -------------------------------------------------------

    def satisfied_tiers(self, device: Device) -> set[str]:
        tiers = {"base"}
        if os.geteuid() == 0:
            tiers.add("admin")
        if _fda_readable():
            tiers.add("fda")
        return tiers

    def capabilities(self, device: Device) -> set[str]:
        tiers = self.satisfied_tiers(device)
        caps = {"application", "persistence"}
        if self.config.file_walk_paths:
            caps.add("file")
        if "fda" in tiers:
            # Both read from FDA-protected locations. Attempting them without the
            # tier would produce a gap on every single run, which is noise, not
            # information — doctor is where the missing tier gets reported.
            caps.add("permission")
            caps.add("browser")
        return caps

    def collect(self, device: Device, modules: set[str], timeout_s: int = 300) -> RawBundle:
        bundle = RawBundle(device=device)
        cfg = self.config

        if "application" in modules:
            _absorb(bundle, "application", apps.collect(check_signatures=cfg.check_signatures))

        if "persistence" in modules:
            _absorb(
                bundle,
                "persistence",
                launchd.collect(
                    include_system=cfg.include_system_launchd,
                    with_login_items=True,
                ),
            )

        if "permission" in modules:
            _absorb(bundle, "permission", tcc.collect())

        if "file" in modules:
            walk = files.collect(
                cfg.file_walk_paths,
                prior_cache=cfg.prior_file_cache,
                max_file_mb=cfg.max_file_mb,
                check_signatures=cfg.check_signatures,
            )
            cfg.new_file_cache = walk.cache
            _absorb(bundle, "file", walk)

        if "browser" in modules:
            _absorb(bundle, "browser", browser.collect())

        return bundle


def _absorb(bundle: RawBundle, category: str, result: ModuleResult) -> None:
    """Fold a module result into the bundle, preserving the ok/gap distinction."""
    bundle.gaps.extend(result.gaps)
    if result.ok:
        bundle.record(category, result.entries)


def _fda_readable() -> bool:
    """Full Disk Access cannot be queried; probe a path only FDA can open."""
    probe = Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    try:
        with probe.open("rb") as f:
            f.read(16)
    except OSError:
        return False
    return True
