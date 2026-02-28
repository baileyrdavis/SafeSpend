from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from guard.risk_engine.types import CheckOutput


@dataclass
class CheckContext:
    site: Any
    previous_scan: Any
    external: Any


class BaseRiskCheck:
    name = ''
    scope = 'GLOBAL'
    version = 1

    def run(self, domain: str, signals: dict[str, Any], context: CheckContext) -> CheckOutput:
        raise NotImplementedError

    def output(
        self,
        *,
        risk_points: int,
        confidence: float,
        severity: str,
        explanation: str,
        evidence: dict[str, Any] | None = None,
    ) -> CheckOutput:
        return CheckOutput(
            check_name=self.name,
            risk_points=risk_points,
            confidence=max(0.0, min(1.0, confidence)),
            severity=severity,
            explanation=explanation,
            evidence=evidence or {},
        )