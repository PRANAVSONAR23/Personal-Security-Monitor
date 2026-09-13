"""SSH transport for the macOS shim.

`ssh <target> 'python3 - --modules ...' < shim/psm_mac_collector.py` — the shim is
piped over stdin, never installed on the Mac. All diagnostics from the shim go to
stderr; stdout is JSON.

Strict host-key checking is left on. First-connection setup is a docs concern.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from psm.collectors.subprocess_util import (
    ProcOutputTooLarge,
    ProcTimeout,
    run,
)

DEFAULT_TIMEOUT_S = 300  # LLD scan timeout


class SshError(RuntimeError):
    pass


class SshNotFound(SshError):
    pass


@dataclass(slots=True)
class SshResult:
    stdout: bytes
    stderr: bytes
    returncode: int


def find_ssh() -> Path:
    path = shutil.which("ssh")
    if not path:
        raise SshNotFound(
            "ssh not found on PATH. Windows 10+ ships an OpenSSH client — enable it under "
            "Settings → Apps → Optional features → 'OpenSSH Client'."
        )
    return Path(path)


def run_shim(
    ssh_target: str,
    shim_path: Path,
    *,
    modules: tuple[str, ...],
    file_walk: tuple[str, ...] = (),
    max_file_mb: int = 200,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> SshResult:
    """Pipe the shim over SSH and return the raw stdout bytes."""
    if not shim_path.exists():
        raise SshError(f"shim not found at {shim_path}")

    ssh = find_ssh()
    remote_cmd_parts = ["python3", "-", "--modules", ",".join(modules)]
    if file_walk:
        remote_cmd_parts.extend(["--file-walk", ":".join(file_walk)])
    remote_cmd_parts.extend(["--max-file-mb", str(max_file_mb)])
    remote_cmd = " ".join(_sh_quote(p) for p in remote_cmd_parts)

    shim_bytes = shim_path.read_bytes()
    argv = [str(ssh), ssh_target, remote_cmd]

    try:
        result = run(argv, timeout_s=timeout_s, input_bytes=shim_bytes)
    except ProcTimeout as e:
        raise SshError(f"ssh timed out: {e}") from e
    except ProcOutputTooLarge as e:
        raise SshError(f"shim output exceeded cap: {e}") from e

    if result.returncode != 0:
        raise SshError(
            f"ssh returned {result.returncode}: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()[:400]}"
        )
    return SshResult(
        stdout=result.stdout, stderr=result.stderr, returncode=result.returncode
    )


def _sh_quote(s: str) -> str:
    if s and all(c.isalnum() or c in "@%+=:,./-" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


DEFAULT_SHIM_PATH = Path(__file__).resolve().parents[3].parent / "shim" / "psm_mac_collector.py"


def default_shim_path() -> Path:
    """Locate the vendored shim next to the source tree.

    Layout: `<repo>/src/psm/collectors/macos/transport.py` → `<repo>/shim/…`.
    """
    return Path(__file__).resolve().parents[4] / "shim" / "psm_mac_collector.py"
