"""Path normalization — frozen at canonical spec v2.

Subject keys and rule predicates always compare normalized paths, so casing and
Unicode form never create phantom events or silently break a join.

v1 normalized every path as a Windows path — backslashes, drive letter, casefold —
including on macOS and Android. That conflated `/Users/Pranav/x` with
`/users/pranav/x` in rule predicates, and it is the reason this is platform-aware
now rather than a single global function.

Per platform:

  windows  backslashes, upper-case drive letter, casefold.
  macos    NFC + casefold. APFS is case-insensitive by default, and macOS hands
           out NFD filenames from some APIs and NFC from others — comparing
           unnormalized forms produces phantom diffs on any accented filename.
  android  NFC only. ext4/f2fs are case-sensitive; folding would merge two files
           that genuinely differ.
"""

from __future__ import annotations

import unicodedata
from typing import Literal

Platform = Literal["windows", "macos", "android"]


def norm_path(p: str, platform: Platform) -> str:
    if platform == "windows":
        p = p.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            p = p[0].upper() + p[1:]
        return p.casefold()
    if platform == "macos":
        return unicodedata.normalize("NFC", p).casefold()
    return unicodedata.normalize("NFC", p)
