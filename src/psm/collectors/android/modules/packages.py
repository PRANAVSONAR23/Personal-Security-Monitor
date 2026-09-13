"""Packages module — `pm list packages` + per-package `dumpsys package`.

Emits `application` items keyed by `pkg:<package-id>`. Extra fields (permissions,
installer) are attached to the payload so the rules engine can join on them without a
second lookup.

Failure model: pm list failure = fatal for this module (gap 'pm-failed'). Individual
dumpsys failures degrade a single package (still emitted with less metadata).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from psm.collectors.android.parsers import dumpsys_package, pm_list
from psm.core.models import CollectionGap

ShellFn = Callable[[str], tuple[int, str, str]]  # (rc, stdout, stderr)


@dataclass(slots=True)
class PackageEntry:
    id: str
    name: str
    version: str | None
    installer: str | None
    source: str
    apk_path: str
    installed_at: str | None
    last_update_time: str | None
    app_id: int | None
    version_code: int | None


def collect(shell: ShellFn) -> tuple[list[dict[str, Any]], list[CollectionGap]]:
    gaps: list[CollectionGap] = []
    rc, stdout, stderr = shell("pm list packages -f -i --show-versioncode")
    if rc != 0:
        return [], [CollectionGap("packages", "pm-failed", stderr.strip()[:200])]

    pm_entries = pm_list.parse(stdout)
    packages: list[dict[str, Any]] = []

    for pm_entry in pm_entries:
        source = pm_list.classify_installer(pm_entry.installer)

        dumped: dumpsys_package.DumpsysPackage | None = None
        rc2, dump_stdout, dump_stderr = shell(f"dumpsys package {pm_entry.pkg}")
        if rc2 == 0:
            dumped = dumpsys_package.parse(dump_stdout)
        else:
            gaps.append(
                CollectionGap(
                    "packages",
                    "dumpsys-failed",
                    f"{pm_entry.pkg}: {dump_stderr.strip()[:120]}",
                )
            )

        packages.append(
            {
                "id": pm_entry.pkg,
                "name": pm_entry.pkg,  # display name comes from labels later; pkg id is the id
                "version": dumped.version_name if dumped else None,
                "version_code": pm_entry.version_code,
                "installer": pm_entry.installer,
                "source": source,
                "apk_path": pm_entry.apk_path,
                "installed_at": dumped.first_install_time if dumped else None,
                "last_update_time": dumped.last_update_time if dumped else None,
                "app_id": dumped.app_id if dumped else None,
            }
        )

    return packages, gaps


def collect_permissions(
    shell: ShellFn, packages: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[CollectionGap]]:
    """Second pass — one `dumpsys package <pkg>` per package to pull runtime perms.

    Split out from `collect()` because permissions and packages become different
    inventory categories with different subject-key schemes.
    """
    perms: list[dict[str, Any]] = []
    gaps: list[CollectionGap] = []
    for entry in packages:
        pkg = entry["id"]
        rc, stdout, stderr = shell(f"dumpsys package {pkg}")
        if rc != 0:
            gaps.append(
                CollectionGap(
                    "permissions",
                    "dumpsys-failed",
                    f"{pkg}: {stderr.strip()[:120]}",
                )
            )
            continue
        dumped = dumpsys_package.parse(stdout)
        if dumped is None:
            continue
        for runtime in dumped.runtime_permissions:
            perms.append(
                {
                    "pkg": pkg,
                    "permission": runtime.permission,
                    "granted": runtime.granted,
                    "flags": list(runtime.flags),
                }
            )
    return perms, gaps
