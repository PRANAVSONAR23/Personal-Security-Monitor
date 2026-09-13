"""Single subprocess helper.

Every external tool (osquery, powershell, adb, ssh) goes through here so timeouts,
output caps, and command logging happen in exactly one place.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_OUTPUT_CAP = 64 * 1024 * 1024  # 64 MB, matches LLD's osquery cap


@dataclass(slots=True)
class ProcResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    truncated: bool


class ProcTimeout(RuntimeError):
    pass


class ProcOutputTooLarge(RuntimeError):
    pass


def run(
    argv: list[str],
    *,
    timeout_s: int,
    output_cap: int = DEFAULT_OUTPUT_CAP,
    input_bytes: bytes | None = None,
    cwd: Path | None = None,
) -> ProcResult:
    """Run argv with a hard timeout and a stdout size cap. stderr is not capped (usually small)."""
    log.debug("exec %s (timeout=%ds cap=%dB)", argv, timeout_s, output_cap)
    try:
        proc = subprocess.run(
            argv,
            input=input_bytes,
            capture_output=True,
            timeout=timeout_s,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ProcTimeout(f"{argv[0]} timed out after {timeout_s}s") from e

    truncated = False
    stdout = proc.stdout or b""
    if len(stdout) > output_cap:
        truncated = True
        raise ProcOutputTooLarge(
            f"{argv[0]} produced {len(stdout)} bytes (cap {output_cap}); refusing to parse"
        )
    return ProcResult(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=proc.stderr or b"",
        truncated=truncated,
    )
