"""Stream sources — Producer pattern, the second collection mode (HLD D3).

A stream has no "previous snapshot", so it never goes through `diff()`. Records
arrive continuously and are evaluated as they land.

Sources are expected to die: the on-device capture agent will be killed by MIUI
under memory pressure, and a capture interface disappears when a hotspot stops.
A source that stops is a normal path — the supervisor records the gap window so
the missing time is visible in reports rather than silently absent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from psm.core.models import utcnow_iso


@dataclass(slots=True)
class SourceHealth:
    running: bool
    records: int = 0
    started_at: str | None = None
    stopped_at: str | None = None
    error: str | None = None
    gaps: list[tuple[str, str]] = field(default_factory=list)  # (from_iso, to_iso)


class StreamSource(ABC):
    kind: str
    requires_tier: str

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """(usable now, human-readable reason when not).

        Checked before starting so a missing prerequisite is explained up front
        rather than surfacing as an obscure failure mid-capture.
        """

    @abstractmethod
    def subscribe(self) -> Iterator[Any]:
        """Yield records until stopped. Must not raise on transient errors."""

    def health(self) -> SourceHealth:
        return SourceHealth(running=False)

    def mark_gap(self, health: SourceHealth, since: str) -> None:
        health.gaps.append((since, utcnow_iso()))
