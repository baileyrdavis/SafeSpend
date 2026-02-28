from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class PaymentFormSecurityCheck(BaseRiskCheck):
    name = 'Payment Form Security Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        payload = signals.get('payment_form_security') or {}
        has_raw_card_form_fields = bool(payload.get('has_raw_card_form_fields'))
        raw_card_form_risk = bool(payload.get('raw_card_form_risk'))
        secure_provider_detected = bool(payload.get('secure_provider_detected'))
        card_form_signal_count = int(payload.get('card_form_signal_count') or 0)

        evidence = {
            'has_raw_card_form_fields': has_raw_card_form_fields,
            'raw_card_form_risk': raw_card_form_risk,
            'secure_provider_detected': secure_provider_detected,
            'card_form_signal_count': card_form_signal_count,
            'card_field_count': int(payload.get('card_field_count') or 0),
            'expiry_field_count': int(payload.get('expiry_field_count') or 0),
            'cvv_field_count': int(payload.get('cvv_field_count') or 0),
            'secure_provider_iframe_count': int(payload.get('secure_provider_iframe_count') or 0),
            'secure_provider_script_count': int(payload.get('secure_provider_script_count') or 0),
            'secure_provider_action_count': int(payload.get('secure_provider_action_count') or 0),
            'evidence': list(payload.get('evidence') or [])[:10],
        }

        if raw_card_form_risk:
            return self.output(
                risk_points=42,
                confidence=0.93,
                severity=Severity.HIGH,
                explanation='Checkout appears to collect raw card details without a recognized hosted payment field provider.',
                evidence=evidence,
            )

        if has_raw_card_form_fields and secure_provider_detected:
            return self.output(
                risk_points=2,
                confidence=0.65,
                severity=Severity.INFO,
                explanation='Card fields were detected alongside a recognized payment provider integration.',
                evidence=evidence,
            )

        if card_form_signal_count == 0:
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='No card-form security signal detected on this page.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.6,
            severity=Severity.INFO,
            explanation='Payment form security signal was inconclusive.',
            evidence=evidence,
        )
