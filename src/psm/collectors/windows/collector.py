"""Windows collector — orchestrates in-process winreg modules and the file hash walker."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from dataclasses import dataclass

from psm.collectors.base import Collector, RawBundle
from psm.collectors.windows.modules import apps, browser, files, persistence
from psm.core.models import Device


@dataclass(slots=True)
class WindowsConfig:
    file_walk_paths: tuple[str, ...] = ()
    max_file_mb: int = files.DEFAULT_MAX_FILE_MB
    prior_file_cache: files.CacheMap | None = None
    new_file_cache: files.CacheMap | None = None  # set on collect(), read by orchestrator
    browser: browser.BrowserConfig | None = None
    include_browser: bool = True


class WindowsCollector(Collector):
    """Capabilities and RawBundle keys use the LLD *category* names
    (persistence / application / file / browser). Modules are an internal collector detail."""

    platform = "windows"
    ALL_MODULES: tuple[str, ...] = ("persistence", "application", "file", "browser")

    def __init__(self, config: WindowsConfig | None = None) -> None:
        self.config = config or WindowsConfig()

    def capabilities(self, device: Device) -> set[str]:
        if sys.platform != "win32":
            return set()
        caps = {"persistence", "application"}
        if self.config.file_walk_paths:
            caps.add("file")
        if self.config.include_browser:
            caps.add("browser")
        return caps

    def collect(
        self,
        device: Device,
        modules: set[str],
        timeout_s: int = 300,
    ) -> RawBundle:
        bundle = RawBundle(device=device)

        if "persistence" in modules:
            entries, gaps = persistence.collect()
            bundle.raw["persistence"] = entries
            bundle.gaps.extend(gaps)

        if "application" in modules:
            entries, gaps = apps.collect()
            bundle.raw["application"] = entries
            bundle.gaps.extend(gaps)

        if "file" in modules:
            result = files.collect(
                self.config.file_walk_paths,
                prior_cache=self.config.prior_file_cache,
                max_file_mb=self.config.max_file_mb,
            )
            bundle.raw["file"] = result.entries
            bundle.gaps.extend(result.gaps)
            self.config.new_file_cache = result.cache

        if "browser" in modules:
            entries, gaps = browser.collect(self.config.browser)
            bundle.raw["browser"] = entries
            bundle.gaps.extend(gaps)

        return bundle


def default_file_walk_paths() -> tuple[str, ...]:
    """Defaults from LLD §9 — conservative for phase 1."""
    return (r"%USERPROFILE%\Downloads", r"%USERPROFILE%\Desktop")


def merge_gaps(*iterables: Iterable) -> list:
    out: list = []
    for it in iterables:
        out.extend(it)
    return out
