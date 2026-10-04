"""Domain models. Serialization uses canonical_json; identity uses subject_key + item_hash."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from psm.normalize.canonical import item_hash

Platform = Literal["macos", "android"]
SnapshotKind = Literal["baseline", "scan", "before", "after"]
EventAction = Literal["added", "removed", "changed", "observed"]
EventSource = Literal["inventory", "hunt", "flowlog", "esf"]
Severity = Literal["info", "notice", "warning", "alert"]
Verdict = Literal["clean", "suspicious", "malicious", "unknown"]
Confidence = Literal["low", "medium", "high"]
ArtifactKind = Literal["file", "apk", "dylib", "script"]
CaptureLeg = Literal["router", "device"]

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
    tiers: set[str] = field(default_factory=lambda: {"base"})
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
    source: EventSource = "inventory"
    snap_to: int | None = None
    before_hash: str | None = None
    after_hash: str | None = None
    snap_from: int | None = None
    ref_id: int | None = None
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


@dataclass(slots=True)
class Artifact:
    """Something an analyzer can look at. Populated from inventory items."""

    device_id: int
    kind: ArtifactKind
    subject_key: str
    sha256: str | None = None
    size: int | None = None
    local_path: str | None = None
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)
    id: int | None = None


@dataclass(slots=True)
class Finding:
    """One analyzer's verdict on one artifact.

    Deliberately not hash-chained: analyzers improve, and re-running an updated
    analyzer over the same artifact must upsert rather than append. Identity is
    (artifact, analyzer, analyzer_version, rule).
    """

    artifact_id: int
    analyzer_id: str
    analyzer_version: str
    verdict: Verdict
    rule_id: str | None = None
    confidence: Confidence = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=utcnow_iso)
    id: int | None = None


@dataclass(slots=True)
class Flow:
    """One observed network flow. High volume — rolled up, retention-capped."""

    device_id: int
    ts: str
    leg: CaptureLeg
    proto: str
    dst_ip: str
    dst_port: int
    src_port: int | None = None
    hostname: str | None = None
    hostname_source: Literal["sni", "dns-query", "dns-cache"] | None = None
    sni_status: Literal["plain", "ech", "none"] | None = None
    app_uid: int | None = None
    app_pkg: str | None = None
    bytes_out: int = 0
    bytes_in: int = 0
    id: int | None = None
