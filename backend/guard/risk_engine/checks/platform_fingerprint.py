from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


KNOWN_PLATFORMS = {'shopify', 'woocommerce', 'magento', 'bigcommerce'}


class EcommercePlatformFingerprintCheck(BaseRiskCheck):
    name = 'E-commerce Platform Fingerprint'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        platform = str(signals.get('platform') or 'unknown').lower()
        custom_checkout = bool(signals.get('custom_checkout', False))

        if platform not in KNOWN_PLATFORMS and custom_checkout:
            return self.output(
                risk_points=10,
                confidence=0.75,
                severity=Severity.WARNING,
                explanation='Unknown e-commerce platform with a custom checkout flow.',
                evidence={'platform': platform, 'custom_checkout': custom_checkout},
            )

        if platform in KNOWN_PLATFORMS:
            return self.output(
                risk_points=0,
                confidence=0.72,
                severity=Severity.INFO,
                explanation='Store appears to use a known e-commerce platform, which is not a standalone trust signal.',
                evidence={'platform': platform},
            )

        return self.output(
            risk_points=0,
            confidence=0.6,
            severity=Severity.INFO,
            explanation='Platform signal was inconclusive.',
            evidence={'platform': platform, 'custom_checkout': custom_checkout},
        )
