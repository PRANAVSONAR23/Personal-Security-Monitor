"""Android collector — orchestrates ADB shell modules.

Capabilities are keyed by category name (matching the Windows collector convention).
The wire between the collector and the ADB layer is a single `ShellFn` callable, so
tests inject a fake shell without touching adb.exe.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from psm.collectors.android import adb
from psm.collectors.android.modules import packages, special_access
from psm.collectors.base import Collector, RawBundle
from psm.core.models import CollectionGap, Device

ShellFn = Callable[[str], tuple[int, str, str]]


@dataclass(slots=True)
class AndroidConfig:
    adb_path: Path | None = None
    shell_fn: ShellFn | None = None  # overrides adb-based shell for tests
    modules: tuple[str, ...] = ("application", "permission")
    sdk_level_override: int | None = None
    detected_sdk_level: int | None = field(default=None)  # populated during collect()


class AndroidCollector(Collector):
    platform = "android"
    ALL_MODULES: tuple[str, ...] = ("application", "permission")

    def __init__(self, config: AndroidConfig | None = None) -> None:
        self.config = config or AndroidConfig()

    def capabilities(self, device: Device) -> set[str]:
        # A device shows up as capable when we have some way to shell into it —
        # a bound shell_fn (tests), a config-supplied adb path, or a detected adb.exe.
        if self.config.shell_fn is not None:
            return set(self.ALL_MODULES)
        try:
            adb.find_adb(str(self.config.adb_path) if self.config.adb_path else None)
        except adb.AdbNotFound:
            return set()
        return set(self.ALL_MODULES)

    def collect(
        self,
        device: Device,
        modules: set[str],
        timeout_s: int = 300,
    ) -> RawBundle:
        bundle = RawBundle(device=device)
        shell = self._resolve_shell(device, bundle.gaps)
        if shell is None:
            return bundle

        # SDK level is recorded on the bundle for downstream (dumpsys parser selection
        # and later reporting). Failure to read it is a soft gap — collection continues.
        self.config.detected_sdk_level = self.config.sdk_level_override
        if self.config.detected_sdk_level is None:
            rc, stdout, _ = shell("getprop ro.build.version.sdk")
            if rc == 0 and stdout.strip().isdigit():
                self.config.detected_sdk_level = int(stdout.strip())
            else:
                bundle.gaps.append(
                    CollectionGap("device", "sdk-unknown", "getprop ro.build.version.sdk failed")
                )

        pkg_entries: list[dict[str, Any]] = []
        if "application" in modules:
            pkg_entries, gaps = packages.collect(shell)
            bundle.raw["application"] = pkg_entries
            bundle.gaps.extend(gaps)

        if "permission" in modules:
            perm_entries, gaps = packages.collect_permissions(shell, pkg_entries)
            special_entries, sgaps = special_access.collect(shell)
            bundle.raw["permission"] = perm_entries + special_entries
            bundle.gaps.extend(gaps)
            bundle.gaps.extend(sgaps)

        return bundle

    def _resolve_shell(
        self, device: Device, gaps: list[CollectionGap]
    ) -> ShellFn | None:
        if self.config.shell_fn is not None:
            return self.config.shell_fn
        try:
            adb_path = adb.find_adb(
                str(self.config.adb_path) if self.config.adb_path else None
            )
        except adb.AdbNotFound as e:
            gaps.append(CollectionGap("device", "adb-missing", str(e)))
            return None

        serial = device.identifier

        def _shell(cmd: str) -> tuple[int, str, str]:
            try:
                result = adb.shell(adb_path, serial, cmd)
            except adb.AdbError as e:
                return (-1, "", str(e))
            return (result.returncode, result.stdout, result.stderr)

        return _shell
