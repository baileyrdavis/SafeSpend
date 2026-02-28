from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class HttpsCheck(BaseRiskCheck):
    name = 'HTTPS Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        is_https = bool(signals.get('is_https', True))
        https_info = context.external.https_info

        if not is_https:
            return self.output(
                risk_points=50,
                confidence=0.95,
                severity=Severity.HIGH,
                explanation='Site appears to be served without HTTPS.',
                evidence={'is_https': is_https},
            )

        if not https_info.get('has_https'):
            return self.output(
                risk_points=30,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='HTTPS endpoint could not be verified.',
                evidence={'error': https_info.get('error')},
            )

        if https_info.get('self_signed'):
            return self.output(
                risk_points=30,
                confidence=0.85,
                severity=Severity.HIGH,
                explanation='HTTPS certificate appears self-signed.',
                evidence={'self_signed': True},
            )

        return self.output(
            risk_points=0,
            confidence=0.9,
            severity=Severity.INFO,
            explanation='HTTPS appears valid.',
            evidence={},
        )