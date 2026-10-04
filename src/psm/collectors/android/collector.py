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
from psm.collectors.android.modules import packages, special_access, storage
from psm.collectors.base import Collector, RawBundle
from psm.core.models import CollectionGap, Device

ShellFn = Callable[[str], tuple[int, str, str]]


@dataclass(slots=True)
class AndroidConfig:
    adb_path: Path | None = None
    shell_fn: ShellFn | None = None  # overrides adb-based shell for tests
    modules: tuple[str, ...] = ("application", "permission", "file")
    storage_roots: tuple[str, ...] = storage.DEFAULT_ROOTS
    max_file_mb: int = storage.DEFAULT_MAX_FILE_MB
    sdk_level_override: int | None = None
    detected_sdk_level: int | None = field(default=None)  # populated during collect()


class AndroidCollector(Collector):
    platform = "android"
    ALL_MODULES: tuple[str, ...] = ("application", "permission", "file")

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
        # One bulk dumpsys yields both categories; see modules/packages.py for
        # why this is not a per-package loop.
        if {"application", "permission"} & modules:
            apps, perms = packages.collect(shell)
            bundle.gaps.extend(apps.gaps)
            if "application" in modules and apps.ok:
                bundle.record("application", apps.entries)

            if "permission" in modules:
                special = special_access.collect(shell)
                bundle.gaps.extend(perms.gaps)
                bundle.gaps.extend(special.gaps)
                # Both feed one category, so both must succeed. Recording the
                # category when only one worked would claim a complete permission
                # set that is missing half its sources — and the next successful
                # scan would then report every missing row as newly added.
                if perms.ok and special.ok:
                    bundle.record("permission", perms.entries + special.entries)

        if "file" in modules and self.config.storage_roots:
            result = storage.collect(
                shell,
                roots=self.config.storage_roots,
                max_file_mb=self.config.max_file_mb,
            )
            bundle.gaps.extend(result.gaps)
            if result.ok:
                bundle.record("file", result.entries)

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
