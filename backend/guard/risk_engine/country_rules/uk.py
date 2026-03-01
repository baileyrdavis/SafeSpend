from guard.models import Severity
from guard.risk_engine.country_rules.base import BaseCountryRule, CountryRuleOutput


class UnitedKingdomCountryRule(BaseCountryRule):
    country_code = 'UK'

    def evaluate(self, signals: dict, domain: str) -> CountryRuleOutput:
        currency = (signals.get('currency') or '').upper()
        destinations = {str(item).upper() for item in (signals.get('shipping_destinations') or [])}

        if currency and currency != 'GBP':
            return CountryRuleOutput(
                risk_points=5,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='United Kingdom indicators conflict with non-GBP pricing.',
                evidence={'currency': currency},
            )

        if destinations and 'UK' not in destinations and 'GB' not in destinations and 'UNITED KINGDOM' not in destinations:
            return CountryRuleOutput(
                risk_points=4,
                confidence=0.6,
                severity=Severity.WARNING,
                explanation='Site appears UK-focused but does not clearly ship to the UK.',
                evidence={'shipping_destinations': sorted(destinations)},
            )

        return CountryRuleOutput(
            risk_points=0,
            confidence=0.65,
            severity=Severity.INFO,
            explanation='UK-specific signals are internally consistent.',
            evidence={'currency': currency or None, 'shipping_destinations': sorted(destinations)},
        )
