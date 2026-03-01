from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class EvidenceCoverageGuardrailCheck(BaseRiskCheck):
    name = 'Evidence Coverage Guardrail'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        enrichment = signals.get('_sitewide_enrichment') or {}
        policies = signals.get('policies') or {}
        contact = signals.get('contact') or {}
        payment_methods = signals.get('payment_methods') or {}
        payment_form = signals.get('payment_form_security') or {}
        dom_features = signals.get('dom_features') or {}

        page_count = int(enrichment.get('page_count') or 0)
        policy_count = sum(bool(policies.get(name)) for name in ('refund', 'privacy', 'terms'))
        contact_count = sum(bool(contact.get(name)) for name in ('email', 'phone', 'contact_page', 'address'))
        has_checkout_context = bool(
            dom_features.get('checkout_route')
            or dom_features.get('cart_route')
            or dom_features.get('checkout_ui_markers')
        )
        methods_count = len(payment_methods.get('methods') or [])
        payment_signal_count = int(payment_form.get('card_form_signal_count') or 0)
        has_payment_context = bool(has_checkout_context or methods_count > 0 or payment_signal_count > 0)

        risk_points = 0
        if page_count <= 1:
            risk_points += 14
        if policy_count == 0:
            risk_points += 10
        if contact_count == 0:
            risk_points += 10
        if not has_checkout_context:
            risk_points += 6
        if not has_payment_context:
            risk_points += 6

        risk_points = min(risk_points, 32)

        evidence = {
            'sitewide_page_count': page_count,
            'policy_count': policy_count,
            'contact_count': contact_count,
            'has_checkout_context': has_checkout_context,
            'payment_methods_count': methods_count,
            'payment_signal_count': payment_signal_count,
        }

        if risk_points >= 24:
            return self.output(
                risk_points=risk_points,
                confidence=0.86,
                severity=Severity.HIGH,
                explanation='Evidence coverage is too limited to classify this site as low risk reliably.',
                evidence=evidence,
            )

        if risk_points > 0:
            return self.output(
                risk_points=risk_points,
                confidence=0.78,
                severity=Severity.WARNING,
                explanation='Evidence coverage is limited, so risk confidence is reduced.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.7,
            severity=Severity.INFO,
            explanation='Evidence coverage appears sufficient for this scan.',
            evidence=evidence,
        )
