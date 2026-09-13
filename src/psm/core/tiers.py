"""Capability tiers (HLD §3).

A tier is a *precondition*, not a platform. Modules declare what they need; a
collector reports which tiers are currently satisfied on a given device. The
orchestrator then runs only the modules whose tier is live.

This exists so the non-root Android path is the complete, supported one while
root-only modules can be declared today and implemented later without changing
any interface. `rooted` is deliberately never satisfied in v2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Tier = Literal["base", "fda", "admin", "rooted"]

ALL_TIERS: tuple[Tier, ...] = ("base", "fda", "admin", "rooted")


@dataclass(frozen=True, slots=True)
class TierInfo:
    tier: Tier
    platform: str
    summary: str
    unlocks: tuple[str, ...]
    how: str


TIER_CATALOG: dict[tuple[str, Tier], TierInfo] = {
    ("macos", "base"): TierInfo(
        tier="base",
        platform="macos",
        summary="ordinary user access",
        unlocks=("applications", "launchd persistence", "user-readable file walk"),
        how="always satisfied",
    ),
    ("macos", "fda"): TierInfo(
        tier="fda",
        platform="macos",
        summary="Full Disk Access granted to the invoking terminal",
        unlocks=("TCC permission database", "browser profile stores", "protected paths"),
        how="System Settings → Privacy & Security → Full Disk Access → add your terminal",
    ),
    ("macos", "admin"): TierInfo(
        tier="admin",
        platform="macos",
        summary="running as root",
        unlocks=("eslogger ESF event stream", "pcap on the Internet Sharing interface"),
        how="run under sudo; SIP can and should stay enabled",
    ),
    ("android", "base"): TierInfo(
        tier="base",
        platform="android",
        summary="adb access to a non-rooted device",
        unlocks=(
            "package inventory",
            "runtime permissions",
            "accessibility and device-admin grants",
            "shared storage walk",
        ),
        how="wireless debugging paired, or USB debugging authorized",
    ),
    ("android", "rooted"): TierInfo(
        tier="rooted",
        platform="android",
        summary="root shell on the device",
        unlocks=(
            "other apps' private storage",
            "process memory inspection",
            "kernel-level hooks",
        ),
        how=(
            "bootloader unlock (Mi Unlock: waiting period + full device wipe) then Magisk. "
            "Trips Play Integrity — banking apps and Google Wallet stop working. "
            "Not satisfied by design in v2"
        ),
    ),
}


def describe(platform: str, tier: Tier) -> TierInfo | None:
    return TIER_CATALOG.get((platform, tier))


def tiers_for(platform: str) -> tuple[Tier, ...]:
    return tuple(t for (p, t) in TIER_CATALOG if p == platform)


def missing(satisfied: set[str], platform: str) -> tuple[TierInfo, ...]:
    """Tiers this platform defines that are not currently satisfied, for `psm doctor`."""
    return tuple(
        info for (p, t), info in TIER_CATALOG.items() if p == platform and t not in satisfied
    )
