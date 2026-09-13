"""Path normalization — frozen spec.

Windows is case-insensitive; subject keys and rule joins always go through norm_path
so casing differences never create phantom events or break joins.
"""

from __future__ import annotations

from typing import Literal

Platform = Literal["windows", "macos", "android"]


def norm_path(p: str, platform: Platform) -> str:
    if platform == "windows":
        p = p.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            p = p[0].upper() + p[1:]
        return p.casefold()
    return p
