from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


RISKY_METHODS = {'gift_card', 'crypto', 'wire_transfer', 'money_transfer', 'payid'}
TRUSTED_METHODS = {'paypal', 'apple_pay', 'google_pay', 'afterpay', 'klarna', 'stripe', 'shop_pay'}


class PaymentMethodRiskCheck(BaseRiskCheck):
    name = 'Payment Method Risk Check'
    scope = 'GLOBAL'
    version = 2

    def run(self, domain, signals, context):
        payment = signals.get('payment_methods') or {}
        methods = {str(item).lower() for item in (payment.get('methods') or [])}
        risky_methods = {str(item).lower() for item in (payment.get('risky_methods') or [])}
        trusted_methods = {str(item).lower() for item in (payment.get('trusted_methods') or [])}
        risky = sorted(risky_methods.intersection(RISKY_METHODS))
        trusted = sorted(trusted_methods.intersection(TRUSTED_METHODS))

        # Backward-compatible fallback for older signal payloads.
        if not risky and not risky_methods:
            risky = sorted(methods.intersection(RISKY_METHODS))
        if not trusted and not trusted_methods:
            trusted = sorted(methods.intersection(TRUSTED_METHODS))

        risky_confidence = float(payment.get('risky_confidence') or 0)
        risky_evidence_count = int(payment.get('risky_evidence_count') or 0)
        risky_is_high_confidence = risky_confidence >= 0.55 or risky_evidence_count >= 1

        evidence = {
            'methods_detected': sorted(methods),
            'risky_methods': risky,
            'trusted_methods': trusted,
            'risky_confidence': risky_confidence,
            'risky_evidence_count': risky_evidence_count,
            'risky_evidence': list(payment.get('risky_evidence') or [])[:8],
        }

        if risky and not risky_is_high_confidence:
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='Potential higher-risk payment methods were mentioned, but evidence was low-confidence.',
                evidence=evidence,
            )

        if len(risky) >= 2:
            return self.output(
                risk_points=28,
                confidence=0.8,
                severity=Severity.HIGH,
                explanation='Multiple higher-risk payment method signals were detected.',
                evidence=evidence,
            )

        if len(risky) == 1 and not trusted:
            return self.output(
                risk_points=18,
                confidence=0.75,
                severity=Severity.WARNING,
                explanation='A higher-risk payment method was detected without trusted alternatives.',
                evidence=evidence,
            )

        if len(risky) == 1:
            return self.output(
                risk_points=10,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='A higher-risk payment method signal was detected.',
                evidence=evidence,
            )

        if trusted:
            return self.output(
                risk_points=0,
                confidence=0.72,
                severity=Severity.INFO,
                explanation='Trusted payment methods were detected, but this does not reduce risk on its own.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.45,
            severity=Severity.INFO,
            explanation='Payment method signals were inconclusive.',
            evidence=evidence,
        )
