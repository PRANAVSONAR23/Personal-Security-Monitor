"""Collector registration.

Importing this module wires every implemented platform into the orchestrator.
"""

from __future__ import annotations

from typing import Any

from psm.collectors.android.collector import AndroidCollector, AndroidConfig
from psm.collectors.base import Collector, Normalizer
from psm.collectors.macos.collector import MacosCollector, MacosConfig
from psm.core.orchestrator import register
from psm.normalize.android import AndroidNormalizer
from psm.normalize.macos import MacosNormalizer


def _android(**kwargs: Any) -> tuple[Collector, Normalizer]:
    cfg = kwargs.get("android_config") or AndroidConfig()
    return AndroidCollector(cfg), AndroidNormalizer()


def _macos(**kwargs: Any) -> tuple[Collector, Normalizer]:
    cfg = kwargs.get("macos_config")
    if cfg is None:
        cfg = MacosConfig()
        walk = kwargs.get("file_walk_paths")
        if walk:
            cfg.file_walk_paths = tuple(walk)
    return MacosCollector(cfg), MacosNormalizer()


def install() -> None:
    register("android", _android)
    register("macos", _macos)


install()
