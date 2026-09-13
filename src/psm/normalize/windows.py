"""Windows normalizer — RawBundle → canonical InventoryItem list.

Subject keys always use norm_path so casing never invents phantom changes.
Display payloads keep the original casing.
"""

from __future__ import annotations

from typing import Any

from psm.collectors.base import Normalizer, RawBundle
from psm.core.models import InventoryItem
from psm.normalize.paths import norm_path


def _persistence_subject(entry: dict[str, Any]) -> str:
    key = f"{entry['hive']}\\{entry['key']}\\{entry['name']}"
    return f"persist:windows:{entry['location']}:{norm_path(key, 'windows')}"


def _file_subject(entry: dict[str, Any]) -> str:
    return f"file:{norm_path(entry['path'], 'windows')}"


def _app_subject(entry: dict[str, Any]) -> str:
    return f"pkg:{entry['id']}"


def _browser_subject(entry: dict[str, Any]) -> str:
    return f"ext:{entry['browser']}:{entry['id']}"


class WindowsNormalizer(Normalizer):
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]:
        items: list[InventoryItem] = []

        for entry in bundle.raw.get("persistence", []) or []:
            items.append(
                InventoryItem(
                    category="persistence",
                    subject_key=_persistence_subject(entry),
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("application", []) or []:
            items.append(
                InventoryItem(
                    category="application",
                    subject_key=_app_subject(entry),
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("file", []) or []:
            items.append(
                InventoryItem(
                    category="file",
                    subject_key=_file_subject(entry),
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("browser", []) or []:
            items.append(
                InventoryItem(
                    category="browser",
                    subject_key=_browser_subject(entry),
                    payload=entry,
                )
            )

        return items
