"""Elevation detection. Never auto-elevate — psm doctor explains what admin adds."""

from __future__ import annotations

import ctypes
import sys


def is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except OSError:
        return False


ELEVATION_ADDS = (
    "HKLM Run keys (all-users startup entries)",
    "the Services registry hive (auto-start services)",
    "scheduled tasks registered under SYSTEM",
    "WMI __EventFilter / CommandLineEventConsumer subscriptions",
)
