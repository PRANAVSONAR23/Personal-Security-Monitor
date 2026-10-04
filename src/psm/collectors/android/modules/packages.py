"""Packages and permissions — from a single bulk `dumpsys package packages` call.

One shell call yields every package's metadata and per-user runtime permissions,
so applications and permissions are parsed from the same text.

Measured over wireless ADB on the POCO M2 Pro (SDK 31, 373 packages):

    dumpsys package packages   5.7 s   one call, 1.9 MB
    dumpsys package <pkg>      2.3 s   x373 = ~14 minutes

v1 issued two per-package calls, so its Android scan could never have met the
90 s budget on this device.
"""

from __future__ import annotations

from collections.abc import Callable

from psm.collectors.android.parsers import dumpsys_packages
from psm.collectors.android.parsers.pm_list import classify_installer
from psm.collectors.base import ModuleResult

ShellFn = Callable[[str], tuple[int, str, str]]  # (rc, stdout, stderr)

BULK_CMD = "dumpsys package packages"
ROSTER_CMD = "pm list packages"

# Runtime permissions worth surfacing. The full set is ~840 rows on a stock
# device, almost all of it uninteresting; these are the ones whose grant is a
# security decision.
SENSITIVE = frozenset(
    {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.CALL_PHONE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.GET_ACCOUNTS",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }
)


def collect(shell: ShellFn, *, sensitive_only: bool = True) -> tuple[ModuleResult, ModuleResult]:
    """Return (applications, permissions) from one bulk dump."""
    apps = ModuleResult()
    perms = ModuleResult()

    # Independent roster first, as a completeness check on the bulk dump below.
    # adb-over-TLS has been observed returning a TRUNCATED dump with exit code 0:
    # one run yielded 295 of 373 packages, parsed cleanly, and would have been
    # stored as the complete inventory. Every later scan would then report the
    # missing 78 as newly installed. A short roster call is the cheapest way to
    # catch that, and silent partial data is the one outcome worth paying for.
    rc, roster_out, roster_err = shell(ROSTER_CMD)
    expected: set[str] = set()
    if rc == 0:
        expected = {
            line.strip().removeprefix("package:")
            for line in roster_out.splitlines()
            if line.strip().startswith("package:")
        }
    else:
        apps.gap("packages", "roster-failed", (roster_err or "").strip()[:120])

    rc, stdout, stderr = shell(BULK_CMD)
    if rc != 0 or "Packages:" not in stdout:
        detail = (stderr or stdout).strip()[:200]
        apps.fail("packages", "dumpsys-failed", detail)
        perms.fail("permissions", "dumpsys-failed", detail)
        return apps, perms

    parsed = dumpsys_packages.parse(stdout)
    if not parsed:
        apps.fail("packages", "dumpsys-unparseable", "no package blocks found")
        perms.fail("permissions", "dumpsys-unparseable", "no package blocks found")
        return apps, perms

    missing = expected - {p.pkg for p in parsed}
    if missing:
        detail = (
            f"{len(missing)} of {len(expected)} packages absent from the dump "
            f"(e.g. {sorted(missing)[:3]}) — treating as truncated"
        )
        apps.fail("packages", "dumpsys-truncated", detail)
        perms.fail("permissions", "dumpsys-truncated", detail)
        return apps, perms

    for p in parsed:
        apps.entries.append(
            {
                "id": p.pkg,
                "name": p.pkg,
                "version": p.version_name,
                "version_code": p.version_code,
                "installer": p.installer,
                "source": classify_installer(p.installer),
                "apk_path": p.code_path,
                "installed_at": p.first_install_time,
                "last_update_time": p.last_update_time,
                "app_id": p.user_id,
                "signing_version": p.signing_version,
                "system": "SYSTEM" in p.flags,
                "installed": p.installed,
                "enabled": p.enabled,
            }
        )
        for rp in p.runtime_permissions:
            if sensitive_only and rp.permission not in SENSITIVE:
                continue
            perms.entries.append(
                {
                    "pkg": p.pkg,
                    "permission": rp.permission,
                    "granted": rp.granted,
                    "flags": list(rp.flags),
                }
            )

    return apps, perms
