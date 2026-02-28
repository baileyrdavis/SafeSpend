from dataclasses import dataclass, field
from typing import Any


@dataclass
class CountryRuleOutput:
    risk_points: int
    confidence: float
    severity: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)


class BaseCountryRule:
    country_code = ''

    def evaluate(self, signals: dict[str, Any], domain: str) -> CountryRuleOutput:
        raise NotImplementedError