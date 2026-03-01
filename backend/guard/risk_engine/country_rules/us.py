from guard.models import Severity
from guard.risk_engine.country_rules.base import BaseCountryRule, CountryRuleOutput


class UnitedStatesCountryRule(BaseCountryRule):
    country_code = 'US'

    def evaluate(self, signals: dict, domain: str) -> CountryRuleOutput:
        currency = (signals.get('currency') or '').upper()
        destinations = {str(item).upper() for item in (signals.get('shipping_destinations') or [])}

        if currency and currency != 'USD':
            return CountryRuleOutput(
                risk_points=5,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='United States indicators conflict with non-USD pricing.',
                evidence={'currency': currency},
            )

        if destinations and 'US' not in destinations and 'USA' not in destinations and 'UNITED STATES' not in destinations:
            return CountryRuleOutput(
                risk_points=4,
                confidence=0.6,
                severity=Severity.WARNING,
                explanation='Site appears US-focused but does not clearly ship to the US.',
                evidence={'shipping_destinations': sorted(destinations)},
            )

        return CountryRuleOutput(
            risk_points=0,
            confidence=0.65,
            severity=Severity.INFO,
            explanation='US-specific signals are internally consistent.',
            evidence={'currency': currency or None, 'shipping_destinations': sorted(destinations)},
        )
