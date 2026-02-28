from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from guard.models import Severity
from guard.risk_engine.checks import DEFAULT_CHECKS
from guard.risk_engine.checks.base import CheckContext
from guard.risk_engine.country import infer_country
from guard.risk_engine.country_rules import get_country_rule
from guard.risk_engine.external import ExternalContext
from guard.risk_engine.types import CheckOutput, EngineResult


@dataclass
class RiskEngine:
    site: Any
    previous_scan: Any = None
    version: int = 1

    def run(self, domain: str, signals: dict[str, Any]) -> EngineResult:
        external = ExternalContext(domain=domain)
        context = CheckContext(
            site=self.site,
            previous_scan=self.previous_scan,
            external=external,
        )

        check_outputs: list[CheckOutput] = []
        for check_class in DEFAULT_CHECKS:
            check = check_class()
            output = check.run(domain=domain, signals=signals, context=context)
            check_outputs.append(output)

        inferred_country, country_confidence, inference_evidence = infer_country(domain, signals)
        country_rule_output = self._run_country_rule(inferred_country, signals, domain, inference_evidence)
        if country_rule_output:
            check_outputs.append(country_rule_output)

        raw_score = sum(item.risk_points for item in check_outputs)
        risk_score = max(0, min(100, raw_score))

        weighted_confidence_total = 0.0
        weight_total = 0.0
        for output in check_outputs:
            weight = max(1, abs(output.risk_points))
            weight_total += weight
            weighted_confidence_total += output.confidence * weight

        score_confidence = round(weighted_confidence_total / weight_total, 3) if weight_total else 0.5

        enriched_signals = {
            '_whois_registrar': external.whois.get('registrar'),
            '_nameservers': external.nameservers,
            '_inferred_country': inferred_country,
            '_country_inference_evidence': inference_evidence,
        }

        return EngineResult(
            risk_score=risk_score,
            score_confidence=score_confidence,
            checks=check_outputs,
            primary_country_guess=inferred_country,
            country_confidence=country_confidence,
            enriched_signals=enriched_signals,
        )

    def _run_country_rule(
        self,
        country_code: str | None,
        signals: dict[str, Any],
        domain: str,
        inference_evidence: dict[str, Any],
    ) -> CheckOutput | None:
        if not country_code:
            return None

        rule = get_country_rule(country_code)
        if not rule:
            return None

        output = rule.evaluate(signals=signals, domain=domain)
        return CheckOutput(
            check_name='Country Consistency Rule',
            risk_points=output.risk_points,
            confidence=output.confidence,
            severity=output.severity if output.risk_points >= 0 else Severity.INFO,
            explanation=output.explanation,
            evidence={
                'country_code': country_code,
                'inference': inference_evidence,
                **output.evidence,
            },
        )