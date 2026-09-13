"""Packages module — `pm list packages` plus one `dumpsys package` per package.

Emits `application` items keyed by `pkg:<package-id>` and hands the captured
dumpsys text back so the permission module can parse it without shelling out
again. v1 ran `dumpsys package <pkg>` twice for every package — once here and
once in `collect_permissions` — roughly 400 ADB round trips for a 200-app phone,
which blows the 90 s budget over wireless on its own.

Failure model: `pm list` failing is fatal for the module (`ok=False`, the whole
category is skipped by the diff). An individual `dumpsys` failing degrades that
one package, which is still emitted with less metadata.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from psm.collectors.android.parsers import dumpsys_package, pm_list
from psm.collectors.base import ModuleResult
from psm.core.models import CollectionGap

ShellFn = Callable[[str], tuple[int, str, str]]  # (rc, stdout, stderr)


@dataclass(slots=True)
class PackageResult(ModuleResult):
    dumps: dict[str, str] = field(default_factory=dict)  # pkg -> raw dumpsys text


def collect(shell: ShellFn) -> PackageResult:
    result = PackageResult()
    rc, stdout, stderr = shell("pm list packages -f -i --show-versioncode")
    if rc != 0:
        result.ok = False
        result.gaps.append(CollectionGap("packages", "pm-failed", stderr.strip()[:200]))
        return result

    for pm_entry in pm_list.parse(stdout):
        source = pm_list.classify_installer(pm_entry.installer)

        dumped: dumpsys_package.DumpsysPackage | None = None
        rc2, dump_stdout, dump_stderr = shell(f"dumpsys package {pm_entry.pkg}")
        if rc2 == 0:
            result.dumps[pm_entry.pkg] = dump_stdout
            dumped = dumpsys_package.parse(dump_stdout)
        else:
            result.gaps.append(
                CollectionGap(
                    "packages",
                    "dumpsys-failed",
                    f"{pm_entry.pkg}: {dump_stderr.strip()[:120]}",
                )
            )

        result.entries.append(
            {
                "id": pm_entry.pkg,
                "name": pm_entry.pkg,
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

    return result


def collect_permissions(dumps: dict[str, str]) -> ModuleResult:
    """Parse runtime permissions out of dumpsys text already captured by collect().

    Pure function of that text — no shell access, so it cannot fail at the ADB
    level. An empty `dumps` means the packages module did not run; the caller
    decides whether that is a gap.
    """
    result = ModuleResult()
    for pkg, text in dumps.items():
        dumped = dumpsys_package.parse(text)
        if dumped is None:
            result.gaps.append(CollectionGap("permissions", "dumpsys-unparseable", pkg))
            continue
        for runtime in dumped.runtime_permissions:
            result.entries.append(
                {
                    "pkg": pkg,
                    "permission": runtime.permission,
                    "granted": runtime.granted,
                    "flags": list(runtime.flags),
                }
            )
    return result
