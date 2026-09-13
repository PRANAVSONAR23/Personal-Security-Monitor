"""ADB wrapper (LLD §3, implementation §3.5).

Locates adb.exe (config path → PATH → bundled) and wraps every call with the shared
subprocess helper (timeout + output cap). All shell commands go via `adb -s SERIAL shell CMD`.

Device states:
- "device"       → online, authorized
- "unauthorized" → user must accept the RSA fingerprint prompt
- "offline"      → cable / driver / power problem
- missing        → OEM USB driver missing (see doctor guidance)

Non-zero exits and parse failures become CollectionGaps upstream — never scan aborts.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from psm.collectors.subprocess_util import (
    ProcOutputTooLarge,
    ProcResult,
    ProcTimeout,
    run,
)

DEFAULT_TIMEOUT_S = 30
SHELL_OUTPUT_CAP = 8 * 1024 * 1024  # LLD §3.5

# 3rd-party OEM guidance surfaced by `psm doctor`.
DRIVER_GUIDANCE = (
    "If the device appears as 'offline' or does not appear at all: install the OEM "
    "USB driver (Samsung/Xiaomi/OnePlus each ship their own) or the Google USB driver "
    "for Pixel devices, then re-run `adb devices`.",
    "If the device shows as 'unauthorized': accept the 'Allow USB debugging?' prompt "
    "on the phone screen and reconnect.",
)


class AdbError(RuntimeError):
    pass


class AdbNotFound(AdbError):
    pass


@dataclass(slots=True)
class AdbDevice:
    serial: str
    state: str  # "device" | "unauthorized" | "offline" | ...


@dataclass(slots=True)
class ShellResult:
    returncode: int
    stdout: str
    stderr: str


def find_adb(config_path: str | None = None) -> Path:
    """Look up `adb.exe` in three places:

    1. Explicit `config_path` (from config.yaml).
    2. `PSM_ADB` env override (useful for tests).
    3. `PATH` (the platform-tools install case).
    4. Bundled `vendor/platform-tools/adb.exe` next to the source tree.
    """
    for candidate in _adb_candidates(config_path):
        if candidate and Path(candidate).exists():
            return Path(candidate)
    raise AdbNotFound(
        "adb.exe not found — install Android platform-tools "
        "(https://developer.android.com/tools/releases/platform-tools) and add it to PATH."
    )


def _adb_candidates(config_path: str | None) -> list[str | None]:
    env_override = os.environ.get("PSM_ADB")
    on_path = shutil.which("adb")
    bundled = str(Path(__file__).resolve().parents[3] / "vendor" / "platform-tools" / "adb.exe")
    return [config_path, env_override, on_path, bundled]


def list_devices(adb: Path, *, timeout_s: int = DEFAULT_TIMEOUT_S) -> list[AdbDevice]:
    """Return every device visible to `adb devices`, whatever state."""
    result = _run_adb([str(adb), "devices"], timeout_s=timeout_s)
    devices: list[AdbDevice] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        serial, state = parts
        devices.append(AdbDevice(serial=serial, state=state))
    return devices


def shell(
    adb: Path,
    serial: str,
    command: str,
    *,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    output_cap: int = SHELL_OUTPUT_CAP,
) -> ShellResult:
    """Run a shell command on the device. Returns stdout as decoded text.

    Non-zero exit is NOT raised — the caller decides how to treat it (usually a gap).
    """
    result = _run_adb(
        [str(adb), "-s", serial, "shell", command],
        timeout_s=timeout_s,
        output_cap=output_cap,
    )
    return ShellResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def get_sdk_level(adb: Path, serial: str, *, timeout_s: int = DEFAULT_TIMEOUT_S) -> int | None:
    """Read `ro.build.version.sdk`. Selects the dumpsys parser downstream."""
    result = shell(adb, serial, "getprop ro.build.version.sdk", timeout_s=timeout_s)
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    if not text.isdigit():
        return None
    return int(text)


def _run_adb(
    argv: list[str], *, timeout_s: int, output_cap: int = SHELL_OUTPUT_CAP
) -> _DecodedResult:
    try:
        proc = run(argv, timeout_s=timeout_s, output_cap=output_cap)
    except ProcTimeout as e:
        raise AdbError(str(e)) from e
    except ProcOutputTooLarge as e:
        raise AdbError(str(e)) from e
    return _decode(proc)


@dataclass(slots=True)
class _DecodedResult:
    returncode: int
    stdout: str
    stderr: str


def _decode(proc: ProcResult) -> _DecodedResult:
    return _DecodedResult(
        returncode=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
    )
