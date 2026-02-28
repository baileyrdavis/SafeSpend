from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class MissingPoliciesCheck(BaseRiskCheck):
    name = 'Missing Policies Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        policies = signals.get('policies') or {}
        refund = bool(policies.get('refund'))
        privacy = bool(policies.get('privacy'))
        terms = bool(policies.get('terms'))

        missing = [
            name
            for name, present in {
                'refund': refund,
                'privacy': privacy,
                'terms': terms,
            }.items()
            if not present
        ]

        if len(missing) >= 2:
            return self.output(
                risk_points=20,
                confidence=0.85,
                severity=Severity.WARNING,
                explanation='At least two standard policies were not detected.',
                evidence={'missing_policies': missing},
            )

        return self.output(
            risk_points=0,
            confidence=0.7,
            severity=Severity.INFO,
            explanation='Policy signals are present or inconclusive.',
            evidence={'missing_policies': missing},
        )