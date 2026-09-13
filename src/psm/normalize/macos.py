"""macOS normalizer — RawBundle → InventoryItem list.

Subject keys (LLD §1):
  application: `pkg:<bundle-id>`
  persistence: `persist:macos:<location>:<name>`
  permission : `perm:<pkg>:<permission>` (TCC service, e.g. kTCCServiceCamera)
  file       : `file:<abs-path>` (macOS paths are case-sensitive; no norm)
"""

from __future__ import annotations

from psm.collectors.base import Normalizer, RawBundle
from psm.core.models import InventoryItem


class MacosNormalizer(Normalizer):
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]:
        items: list[InventoryItem] = []

        for entry in bundle.raw.get("application", []) or []:
            items.append(
                InventoryItem(
                    category="application",
                    subject_key=f"pkg:{entry['id']}",
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("persistence", []) or []:
            items.append(
                InventoryItem(
                    category="persistence",
                    subject_key=f"persist:macos:{entry['location']}:{entry['name']}",
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("permission", []) or []:
            items.append(
                InventoryItem(
                    category="permission",
                    subject_key=f"perm:{entry['pkg']}:{entry['permission']}",
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("file", []) or []:
            items.append(
                InventoryItem(
                    category="file",
                    subject_key=f"file:{entry['path']}",
                    payload=entry,
                )
            )

        for entry in bundle.raw.get("browser", []) or []:
            items.append(
                InventoryItem(
                    category="browser",
                    subject_key=f"ext:{entry['browser']}:{entry['id']}",
                    payload=entry,
                )
            )

        return items
