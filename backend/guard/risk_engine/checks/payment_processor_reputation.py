from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


REPUTABLE_PROCESSORS = {
    'stripe',
    'paypal',
    'braintree',
    'adyen',
    'square',
    'shopify',
    'amazon pay',
    'checkout.com',
}


class PaymentProcessorReputationCheck(BaseRiskCheck):
    name = 'Payment Processor Reputation Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        payment_form = signals.get('payment_form_security') or {}
        payment_methods = signals.get('payment_methods') or {}
        dom_features = signals.get('dom_features') or {}

        trusted_providers = {
            str(item).lower().strip()
            for item in (payment_form.get('trusted_providers') or [])
            if str(item).strip()
        }
        trusted_methods = {
            str(item).lower().strip()
            for item in (payment_methods.get('trusted_methods') or [])
            if str(item).strip()
        }
        has_checkout_context = bool(
            dom_features.get('checkout_route')
            or dom_features.get('cart_route')
            or dom_features.get('checkout_ui_markers')
        )
        has_raw_card_form_fields = bool(payment_form.get('has_raw_card_form_fields'))
        has_reputable_provider_signal = bool(trusted_providers.intersection(REPUTABLE_PROCESSORS))
        has_reputable_method_signal = bool(trusted_methods)

        evidence = {
            'has_checkout_context': has_checkout_context,
            'has_raw_card_form_fields': has_raw_card_form_fields,
            'trusted_providers': sorted(trusted_providers),
            'trusted_methods': sorted(trusted_methods),
            'has_reputable_provider_signal': has_reputable_provider_signal,
            'has_reputable_method_signal': has_reputable_method_signal,
        }

        if has_raw_card_form_fields and not has_reputable_provider_signal:
            return self.output(
                risk_points=12,
                confidence=0.82,
                severity=Severity.WARNING,
                explanation='Checkout card form did not show a reputable hosted payment processor signal.',
                evidence=evidence,
            )

        if has_checkout_context and not has_reputable_provider_signal and not has_reputable_method_signal:
            return self.output(
                risk_points=6,
                confidence=0.68,
                severity=Severity.WARNING,
                explanation='No reputable payment processor indicators were detected on the checkout flow.',
                evidence=evidence,
            )

        if has_reputable_provider_signal or has_reputable_method_signal:
            return self.output(
                risk_points=-4,
                confidence=0.74,
                severity=Severity.INFO,
                explanation='Reputable payment processor indicators were detected.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.52,
            severity=Severity.INFO,
            explanation='Payment processor reputation signal was inconclusive.',
            evidence=evidence,
        )
