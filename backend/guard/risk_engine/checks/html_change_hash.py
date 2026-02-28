from datetime import timedelta

from django.utils import timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class HtmlChangeHashCheck(BaseRiskCheck):
    name = 'HTML Change Hash Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        current_hash = signals.get('html_hash')
        previous_scan = context.previous_scan

        if not previous_scan:
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='No previous scan available for HTML hash comparison.',
                evidence={'current_hash_present': bool(current_hash)},
            )

        previous_hash = (previous_scan.raw_signals or {}).get('html_hash')
        previous_signals = previous_scan.raw_signals or {}
        if not current_hash or not previous_hash:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='HTML hash comparison was inconclusive.',
                evidence={'current_hash_present': bool(current_hash), 'previous_hash_present': bool(previous_hash)},
            )

        policies_changed = (signals.get('policies') or {}) != (previous_signals.get('policies') or {})
        payment_changed = (signals.get('payment_methods') or {}) != (previous_signals.get('payment_methods') or {})
        checkout_changed = str(signals.get('checkout_domain') or '') != str(previous_signals.get('checkout_domain') or '')
        contact_profile_changed = str(signals.get('contact_profile_hash') or '') != str(previous_signals.get('contact_profile_hash') or '')
        address_profile_changed = str(signals.get('address_profile_hash') or '') != str(previous_signals.get('address_profile_hash') or '')
        meaningful_change_count = sum(
            bool(item)
            for item in [policies_changed, payment_changed, checkout_changed, contact_profile_changed, address_profile_changed]
        )

        evidence = {
            'previous_hash': previous_hash,
            'current_hash': current_hash,
            'policies_changed': policies_changed,
            'payment_changed': payment_changed,
            'checkout_changed': checkout_changed,
            'contact_profile_changed': contact_profile_changed,
            'address_profile_changed': address_profile_changed,
            'meaningful_change_count': meaningful_change_count,
        }

        if (
            current_hash != previous_hash
            and previous_scan.scanned_at >= timezone.now() - timedelta(days=30)
            and meaningful_change_count >= 2
        ):
            return self.output(
                risk_points=6,
                confidence=0.7,
                severity=Severity.WARNING,
                explanation='Multiple stability signals changed since the recent previous scan.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.75,
            severity=Severity.INFO,
            explanation='No suspicious short-term multi-signal change detected.',
            evidence=evidence,
        )
