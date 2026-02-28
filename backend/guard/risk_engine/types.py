from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckOutput:
    check_name: str
    risk_points: int
    confidence: float
    severity: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineResult:
    risk_score: int
    score_confidence: float
    checks: list[CheckOutput]
    primary_country_guess: str | None
    country_confidence: float
    enriched_signals: dict[str, Any] = field(default_factory=dict)