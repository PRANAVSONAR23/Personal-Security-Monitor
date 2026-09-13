"""Android normalizer — RawBundle → InventoryItem list.

Subject key formats (LLD §1):
  application: `pkg:<package-id>`
  permission : `perm:<package-id>:<permission>`

For permissions, the subject key intentionally includes the permission — so revoking
a runtime permission surfaces as `permission removed` rather than `changed`.
"""

from __future__ import annotations

from typing import Any

from psm.collectors.base import Normalizer, RawBundle
from psm.core.models import InventoryItem


class AndroidNormalizer(Normalizer):
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

        for entry in bundle.raw.get("permission", []) or []:
            payload: dict[str, Any] = dict(entry)
            items.append(
                InventoryItem(
                    category="permission",
                    subject_key=f"perm:{entry['pkg']}:{entry['permission']}",
                    payload=payload,
                )
            )

        return items
