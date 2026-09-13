"""Collector interface (LLD §4) — poll mode, Adapter pattern.

The important contract here is `RawBundle.collected`. A snapshot's stored
capability set is written from that field, never from a declared constant.

v1 declared capabilities optimistically: the macOS collector returned all five
categories whenever *any* envelope was present, regardless of what the envelope
actually contained. Diffing a snapshot that declared `application` but carried no
applications against one that did produced 64 phantom "application removed"
events in a single scan. Capability negotiation exists precisely to prevent that,
and declaring rather than deriving defeats it.

Rule: a module lands in `collected` only when it ran and produced a result —
including a legitimately empty result. A module that failed records a gap and
stays out of `collected`, so the diff skips that category entirely instead of
reporting everything in it as removed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from psm.core.models import CollectionGap, Device, InventoryItem, utcnow_iso


@dataclass(slots=True)
class ModuleResult:
    """What one collection module returns.

    `ok` is the F1 distinction: a module that ran and found nothing is ok with an
    empty `entries` list, and its category still counts as collected. A module
    that could not look sets ok=False, and the category is left out of the
    snapshot entirely so the diff skips it.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[CollectionGap] = field(default_factory=list)
    ok: bool = True

    def gap(self, module: str, reason: str, detail: str = "") -> None:
        self.gaps.append(CollectionGap(module=module, reason=reason, detail=detail))

    def fail(self, module: str, reason: str, detail: str = "") -> ModuleResult:
        self.ok = False
        self.gap(module, reason, detail)
        return self


@dataclass(slots=True)
class RawBundle:
    device: Device
    taken_at: str = field(default_factory=utcnow_iso)
    raw: dict[str, Any] = field(default_factory=dict)
    gaps: list[CollectionGap] = field(default_factory=list)
    collected: set[str] = field(default_factory=set)

    def record(self, category: str, entries: list[dict[str, Any]]) -> None:
        """Register a module's output. An empty list is a valid result and still
        counts as collected — 'nothing there' and 'could not look' are different,
        and only the caller knows which one this is."""
        self.raw[category] = entries
        self.collected.add(category)

    def record_gap(self, module: str, reason: str, detail: str = "") -> None:
        """Register a module that could not produce a result. Deliberately does
        NOT add to `collected`, so the diff skips the category."""
        self.gaps.append(CollectionGap(module=module, reason=reason, detail=detail))


FileCache = dict[str, tuple[int, int, int, str]]  # path_norm -> (size, mtime_ns, inode, sha256)


@runtime_checkable
class FileCacheAware(Protocol):
    """A collector that benefits from a persisted (stat -> sha256) cache.

    The controller owns storage: it loads the cache before `collect()` and reads
    the updated one after. The collector never touches the database, and the
    controller never interprets the cache contents.
    """

    def load_file_cache(self, cache: FileCache) -> None: ...
    def dump_file_cache(self) -> FileCache: ...


class CollectionError(Exception):
    """Raised by a module when it cannot produce output; caught by the collector as a gap."""

    def __init__(self, module: str, reason: str, detail: str = "") -> None:
        super().__init__(f"{module}: {reason} ({detail})" if detail else f"{module}: {reason}")
        self.module = module
        self.reason = reason
        self.detail = detail


class Collector(ABC):
    platform: str
    ALL_MODULES: tuple[str, ...]

    @abstractmethod
    def satisfied_tiers(self, device: Device) -> set[str]:
        """Which capability tiers are live for this device right now."""

    @abstractmethod
    def capabilities(self, device: Device) -> set[str]:
        """Modules this collector could produce for the given device right now.

        This is a *plan*, used to choose what to attempt. The snapshot's stored
        capability set comes from RawBundle.collected — what actually worked.
        """

    @abstractmethod
    def collect(self, device: Device, modules: set[str], timeout_s: int = 300) -> RawBundle: ...


class Normalizer(ABC):
    @abstractmethod
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]: ...
