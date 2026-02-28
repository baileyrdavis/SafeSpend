from tldextract import extract

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


TRUSTED_CHECKOUT_DOMAINS = {
    'paypal.com',
    'stripe.com',
    'shopify.com',
    'shop.app',
    'bigcommerce.com',
    'square.site',
}


def _registered_domain(hostname: str) -> str:
    parsed = extract(hostname)
    return parsed.top_domain_under_public_suffix or hostname


class CheckoutRedirectCheck(BaseRiskCheck):
    name = 'Checkout Redirect Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        checkout_domain = (signals.get('checkout_domain') or '').lower()
        if not checkout_domain:
            return self.output(
                risk_points=0,
                confidence=0.55,
                severity=Severity.INFO,
                explanation='No checkout domain was detected for comparison.',
                evidence={},
            )

        root_domain = _registered_domain(domain)
        checkout_root = _registered_domain(checkout_domain)

        if checkout_root == root_domain:
            return self.output(
                risk_points=0,
                confidence=0.8,
                severity=Severity.INFO,
                explanation='Checkout remains on the same registered domain.',
                evidence={'checkout_domain': checkout_domain},
            )

        if any(checkout_root.endswith(trusted) for trusted in TRUSTED_CHECKOUT_DOMAINS):
            return self.output(
                risk_points=5,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='Checkout redirects externally via a known processor.',
                evidence={'checkout_domain': checkout_domain},
            )

        return self.output(
            risk_points=20,
            confidence=0.85,
            severity=Severity.HIGH,
            explanation='Checkout redirects to an unrelated external domain.',
            evidence={'checkout_domain': checkout_domain},
        )
