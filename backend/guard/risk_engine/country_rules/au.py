from guard.models import Severity
from guard.risk_engine.country_rules.base import BaseCountryRule, CountryRuleOutput


class AustraliaCountryRule(BaseCountryRule):
    country_code = 'AU'

    def evaluate(self, signals: dict, domain: str) -> CountryRuleOutput:
        currency = (signals.get('currency') or '').upper()
        destinations = {str(item).upper() for item in (signals.get('shipping_destinations') or [])}

        if currency and currency != 'AUD':
            return CountryRuleOutput(
                risk_points=5,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='Australia indicators conflict with non-AUD pricing.',
                evidence={'currency': currency},
            )

        if destinations and 'AU' not in destinations and 'AUSTRALIA' not in destinations:
            return CountryRuleOutput(
                risk_points=5,
                confidence=0.65,
                severity=Severity.WARNING,
                explanation='Site appears Australian but does not clearly ship to Australia.',
                evidence={'shipping_destinations': sorted(destinations)},
            )

        return CountryRuleOutput(
            risk_points=0,
            confidence=0.7,
            severity=Severity.INFO,
            explanation='Australia-specific signals are internally consistent.',
            evidence={'currency': currency or None, 'shipping_destinations': sorted(destinations)},
        )
