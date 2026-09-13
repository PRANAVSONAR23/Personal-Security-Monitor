"""Explain templates — per-(category, action) markdown files, slot-filled from payloads."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates" / "explain"


class _SafeMap(dict):
    def __missing__(self, key: str) -> str:
        return "(unknown)"


def _payload_view(payload: dict[str, Any]) -> dict[str, Any]:
    """Add derived display fields; keep original keys intact for format_map."""
    view: dict[str, Any] = defaultdict(lambda: "(unknown)")
    view.update(payload)
    args = payload.get("args")
    view["args_joined"] = " ".join(args) if isinstance(args, list) else ""
    return view


def _candidate_names(category: str, action: str, payload: dict[str, Any]) -> list[str]:
    names = []
    if category == "persistence":
        location = payload.get("location")
        if location:
            names.append(f"{category}_{action}_{location}")
    if category == "permission":
        perm = payload.get("permission")
        if isinstance(perm, str) and perm.startswith("special:"):
            names.append(f"{category}_{action}_{perm.split(':', 1)[1]}")
    if category == "application":
        source = payload.get("source")
        if source:
            names.append(f"{category}_{action}_{source}")
    names.append(f"{category}_{action}")
    names.append(f"{category}")
    return names


def render(category: str, action: str, payload: dict[str, Any]) -> str:
    for stem in _candidate_names(category, action, payload):
        path = TEMPLATES_DIR / f"{stem}.md"
        if path.exists():
            template = path.read_text(encoding="utf-8")
            view = _payload_view(payload)
            return template.format_map(_SafeMap(view))
    return (
        f"# {category} {action}\n\n"
        f"(no explanation template shipped for this event type yet)\n"
    )
