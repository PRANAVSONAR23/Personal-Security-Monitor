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

    def satisfied_tiers(self, device: Device) -> set[str]:
        """`base` when we can shell in. `rooted` is never satisfied in v2 by design."""
        if self.config.shell_fn is not None:
            return {"base"}
        try:
            adb.find_adb(str(self.config.adb_path) if self.config.adb_path else None)
        except adb.AdbNotFound:
            return set()
        return {"base"}

    def capabilities(self, device: Device) -> set[str]:
        """What we will *attempt*. What actually lands is RawBundle.collected."""
        if not self.satisfied_tiers(device):
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
                bundle.record_gap("device", "sdk-unknown", "getprop ro.build.version.sdk failed")

        # F1: record() marks a category collected; a module that fails records a
        # gap and stays out of `collected`, so the diff skips it rather than
        # reporting every item in it as removed.
        pkg_entries: list[dict[str, Any]] = []
        dumps: dict[str, str] = {}
        if "application" in modules:
            result = packages.collect(shell)
            bundle.gaps.extend(result.gaps)
            if result.ok:
                pkg_entries = result.entries
                dumps = result.dumps
                bundle.record("application", pkg_entries)

        if "permission" in modules:
            # Reuses the dumpsys output already captured above — v1 shelled out a
            # second time per package, doubling ADB round trips.
            perm_result = packages.collect_permissions(dumps)
            special_result = special_access.collect(shell)
            bundle.gaps.extend(perm_result.gaps)
            bundle.gaps.extend(special_result.gaps)
            if perm_result.ok or special_result.ok:
                bundle.record("permission", perm_result.entries + special_result.entries)

        return bundle

    def _resolve_shell(self, device: Device, gaps: list[Any]) -> ShellFn | None:
        if self.config.shell_fn is not None:
            return self.config.shell_fn
        try:
            adb_path = adb.find_adb(str(self.config.adb_path) if self.config.adb_path else None)
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
