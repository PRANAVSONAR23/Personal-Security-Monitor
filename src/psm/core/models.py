"""Domain models. Serialization uses canonical_json; identity uses subject_key + item_hash."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from psm.normalize.canonical import item_hash

Platform = Literal["windows", "macos", "android"]
SnapshotKind = Literal["baseline", "scan", "before", "after"]
EventAction = Literal["added", "removed", "changed", "observed"]
Severity = Literal["info", "notice", "warning", "alert"]

ItemCategory = Literal[
    "file",
    "application",
    "permission",
    "persistence",
    "network",
    "browser",
    "process",
]


def utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class Device:
    name: str
    platform: Platform
    identifier: str
    created_at: str = field(default_factory=utcnow_iso)
    meta: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass(slots=True)
class CollectionGap:
    module: str
    reason: str
    detail: str = ""


@dataclass(slots=True)
class Snapshot:
    device_id: int
    kind: SnapshotKind
    capabilities: set[str]
    tool_version: str
    taken_at: str = field(default_factory=utcnow_iso)
    gaps: list[CollectionGap] = field(default_factory=list)
    id: int | None = None


@dataclass(slots=True)
class InventoryItem:
    category: str
    subject_key: str
    payload: dict[str, Any]

    @property
    def hash(self) -> str:
        return item_hash(self.payload)


@dataclass(slots=True)
class Event:
    device_id: int
    ts: str
    category: str
    action: EventAction
    subject_key: str
    snap_to: int
    before_hash: str | None = None
    after_hash: str | None = None
    snap_from: int | None = None
    severity: Severity = "info"
    prev_row_hash: str = ""
    row_hash: str = ""
    id: int | None = None


@dataclass(slots=True)
class Alert:
    rule_id: str
    device_id: int
    title: str
    detail: dict[str, Any]
    ts: str = field(default_factory=utcnow_iso)
    status: Literal["open", "ack", "closed"] = "open"
    id: int | None = None
