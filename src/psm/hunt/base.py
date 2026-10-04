"""Analyzer contract — Strategy pattern.

An analyzer looks at one artifact plus the inventory payload already collected
for it, and returns findings. It does no device I/O and opens no sockets: by the
time it runs, everything it needs is in hand. That keeps hunt runnable offline,
repeatable, and fast enough to re-run over the whole inventory.

Every finding names the analyzer, its version, the rule that matched, and the
evidence. An unexplainable verdict is worse than no verdict.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from psm.core.models import Artifact, ArtifactKind, Confidence, Finding, Verdict


class Analyzer(ABC):
    id: str
    version: str
    accepts: tuple[ArtifactKind, ...]

    @abstractmethod
    def analyze(self, artifact: Artifact, payload: dict[str, Any]) -> list[Finding]: ...

    def finding(
        self,
        artifact: Artifact,
        *,
        rule_id: str,
        verdict: Verdict,
        confidence: Confidence = "medium",
        **evidence: Any,
    ) -> Finding:
        assert artifact.id is not None
        return Finding(
            artifact_id=artifact.id,
            analyzer_id=self.id,
            analyzer_version=self.version,
            rule_id=rule_id,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
        )
