"""Code signature status via `codesign`.

`codesign -dv` costs about 6 ms per binary, which is affordable inside the file
walk. `spctl -a` (Gatekeeper assessment, which is what reports notarization)
costs about 670 ms and is deliberately NOT used here — it would dominate the
45 s snapshot budget.

Status values are chosen so that "we did not determine it" is distinguishable
from "we determined it is unsigned". v1 emitted `unknown` for every file and the
shipped rule treated `unknown` as alert-worthy, so every new file in a user
directory fired an alert. Alerting on our own ignorance is not detection.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from psm.collectors.subprocess_util import ProcTimeout, run

SignatureStatus = Literal["valid", "adhoc", "unsigned", "invalid", "unknown"]

_NOT_SIGNED = re.compile(r"code object is not signed at all", re.I)
_ADHOC = re.compile(r"flags=0x\d*2\b|\badhoc\b", re.I)
_AUTHORITY = re.compile(r"^Authority=(.+)$", re.M)
_TEAM = re.compile(r"^TeamIdentifier=(.+)$", re.M)


class SignatureInfo:
    __slots__ = ("authority", "status", "team_id")

    def __init__(
        self,
        status: SignatureStatus = "unknown",
        authority: str | None = None,
        team_id: str | None = None,
    ) -> None:
        self.status = status
        self.authority = authority
        self.team_id = team_id

    def as_payload(self) -> dict[str, str | None]:
        return {
            "signature_status": self.status,
            "signer": self.authority,
            "team_id": self.team_id,
        }


def check(path: Path | str, *, timeout_s: int = 10) -> SignatureInfo:
    """Best-effort signature status. Never raises — an unreadable target is `unknown`."""
    try:
        result = run(["/usr/bin/codesign", "-dv", "--verbose=2", str(path)], timeout_s=timeout_s)
    except (ProcTimeout, OSError):
        return SignatureInfo("unknown")

    # codesign writes its report to stderr even on success.
    text = result.stderr.decode("utf-8", errors="replace")

    if _NOT_SIGNED.search(text):
        return SignatureInfo("unsigned")
    if result.returncode != 0:
        return SignatureInfo("invalid")

    authority = None
    m = _AUTHORITY.search(text)
    if m:
        authority = m.group(1).strip()
    team = None
    t = _TEAM.search(text)
    if t and t.group(1).strip() != "not set":
        team = t.group(1).strip()

    if authority is None and _ADHOC.search(text):
        return SignatureInfo("adhoc", authority=None, team_id=team)
    if authority is None:
        return SignatureInfo("adhoc", team_id=team)
    return SignatureInfo("valid", authority=authority, team_id=team)
