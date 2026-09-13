"""Collector interface (LLD §3). Raw bundle carries per-module payload plus collection gaps."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from psm.core.models import CollectionGap, Device, InventoryItem, utcnow_iso


@dataclass(slots=True)
class RawBundle:
    device: Device
    taken_at: str = field(default_factory=utcnow_iso)
    raw: dict[str, Any] = field(default_factory=dict)
    gaps: list[CollectionGap] = field(default_factory=list)


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
    def capabilities(self, device: Device) -> set[str]:
        """Modules this collector can produce for the given device *right now*."""

    @abstractmethod
    def collect(
        self,
        device: Device,
        modules: set[str],
        timeout_s: int = 300,
    ) -> RawBundle: ...


class Normalizer(ABC):
    @abstractmethod
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]: ...
