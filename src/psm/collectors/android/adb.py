"""ADB wrapper (LLD §4).

Locates adb (config path → PSM_ADB → ANDROID_HOME → PATH) and wraps every call with the shared
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
# macOS needs no USB drivers for adb — the v1 OEM-driver guidance was a Windows
# concern and is gone. What remains are the states that actually occur here.
CONNECT_GUIDANCE = (
    "'unauthorized': accept the 'Allow USB debugging?' prompt on the phone, then "
    "re-run `adb devices`.",
    "'offline' or absent over Wi-Fi: the pairing expired or the phone changed IP. "
    "Re-pair with `adb pair <host>:<port>` then `adb connect <host>:<port>`.",
    "On MIUI, 'Wireless debugging' lives under Developer options and switches off "
    "after a reboot; USB debugging (Security settings) must also be on to install.",
)
DRIVER_GUIDANCE = CONNECT_GUIDANCE  # back-compat alias


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
    """Look up `adb` in order:

    1. Explicit `config_path` (from config.yaml).
    2. `PSM_ADB` env override.
    3. `$ANDROID_HOME/platform-tools/adb`.
    4. `PATH`.
    5. The Homebrew commandlinetools location, which is not on PATH by default.
    """
    for candidate in _adb_candidates(config_path):
        if candidate and Path(candidate).exists():
            return Path(candidate)
    raise AdbNotFound(
        "adb not found. Install platform-tools (`brew install --cask android-commandlinetools`) "
        "or set PSM_ADB / ANDROID_HOME. On this machine it lives at "
        "$ANDROID_HOME/platform-tools/adb and is not on PATH."
    )


def _adb_candidates(config_path: str | None) -> list[str | None]:
    env_override = os.environ.get("PSM_ADB")
    android_home = os.environ.get("ANDROID_HOME")
    from_home = str(Path(android_home) / "platform-tools" / "adb") if android_home else None
    on_path = shutil.which("adb")
    well_known = "/opt/homebrew/share/android-commandlinetools/platform-tools/adb"
    return [config_path, env_override, from_home, on_path, well_known]


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
