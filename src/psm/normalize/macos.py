"""macOS normalizer — RawBundle → InventoryItem list.

Subject keys:
  application  pkg:<bundle-id>
  persistence  persist:macos:<location>:<scope>:<name>          (launchd jobs)
               persist:macos:loginitem:<uid>:<uuid>             (BTM login items)
  permission   perm:<scope>:<client>:<service>[:<target>]
  file         file:<abs-path>
  browser      ext:<browser>:<profile>:<extension-id>

The permission key carries scope and target because TCC's own primary key is
(service, client, client_type, indirect_object_identifier): two rows such as
"DeskTime may drive Brave" and "DeskTime may drive Chrome" are distinct grants
and must not collapse into one item.

The browser key carries the profile because the same extension installed in two
Chrome profiles is two independent installs with independent permissions.
"""

from __future__ import annotations

from typing import Any

from psm.collectors.base import Normalizer, RawBundle
from psm.core.models import InventoryItem


class MacosNormalizer(Normalizer):
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]:
        items: list[InventoryItem] = []

        for entry in bundle.raw.get("application", []) or []:
            items.append(InventoryItem("application", f"pkg:{entry['id']}", entry))

        for entry in bundle.raw.get("persistence", []) or []:
            items.append(InventoryItem("persistence", _persistence_key(entry), entry))

        for entry in bundle.raw.get("permission", []) or []:
            items.append(InventoryItem("permission", _permission_key(entry), entry))

        for entry in bundle.raw.get("file", []) or []:
            items.append(InventoryItem("file", f"file:{entry['path']}", entry))

        for entry in bundle.raw.get("browser", []) or []:
            items.append(
                InventoryItem(
                    "browser",
                    f"ext:{entry['browser']}:{entry.get('profile', 'default')}:{entry['id']}",
                    entry,
                )
            )

        return items


def _persistence_key(entry: dict[str, Any]) -> str:
    location = entry.get("location", "unknown")
    if location == "loginitem":
        ident = entry.get("uuid") or entry.get("identifier") or entry["name"]
        return f"persist:macos:loginitem:{entry.get('uid', '?')}:{ident}"
    return f"persist:macos:{location}:{entry.get('scope', 'user')}:{entry['name']}"


def _permission_key(entry: dict[str, Any]) -> str:
    base = f"perm:{entry.get('scope', 'user')}:{entry['pkg']}:{entry['permission']}"
    target = entry.get("target")
    return f"{base}:{target}" if target else base
