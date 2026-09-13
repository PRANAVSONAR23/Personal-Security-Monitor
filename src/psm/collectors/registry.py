"""Collector registration.

Importing this module wires every implemented platform into the orchestrator.
macOS lands in Phase 1; until then it is deliberately absent, so asking for it
fails loudly instead of silently collecting nothing.
"""

from __future__ import annotations

from typing import Any

from psm.collectors.android.collector import AndroidCollector, AndroidConfig
from psm.collectors.base import Collector, Normalizer
from psm.core.orchestrator import register
from psm.normalize.android import AndroidNormalizer


def _android(**kwargs: Any) -> tuple[Collector, Normalizer]:
    cfg = kwargs.get("android_config") or AndroidConfig()
    return AndroidCollector(cfg), AndroidNormalizer()


def install() -> None:
    register("android", _android)


install()
