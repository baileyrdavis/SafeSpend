from datetime import timedelta

from django.utils import timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class ContactDetailsChangeCheck(BaseRiskCheck):
    name = 'Contact Details Change Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        previous_scan = context.previous_scan
        current_contact_hash = str(signals.get('contact_profile_hash') or '')
        current_address_hash = str(signals.get('address_profile_hash') or '')

        if not previous_scan:
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='No previous scan available for contact detail comparison.',
                evidence={'current_contact_hash_present': bool(current_contact_hash), 'current_address_hash_present': bool(current_address_hash)},
            )

        previous_signals = previous_scan.raw_signals or {}
        previous_contact_hash = str(previous_signals.get('contact_profile_hash') or '')
        previous_address_hash = str(previous_signals.get('address_profile_hash') or '')

        if not current_contact_hash or not previous_contact_hash:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='Contact detail comparison was inconclusive.',
                evidence={
                    'current_contact_hash_present': bool(current_contact_hash),
                    'previous_contact_hash_present': bool(previous_contact_hash),
                },
            )

        contact_changed = current_contact_hash != previous_contact_hash
        address_changed = bool(current_address_hash and previous_address_hash and current_address_hash != previous_address_hash)
        changed_recently = previous_scan.scanned_at >= timezone.now() - timedelta(days=30)

        evidence = {
            'contact_changed': contact_changed,
            'address_changed': address_changed,
            'changed_recently_window_days': 30,
            'previous_scan_at': previous_scan.scanned_at.isoformat(),
        }

        if changed_recently and (contact_changed or address_changed):
            risk_points = 12 if contact_changed and address_changed else 8
            return self.output(
                risk_points=risk_points,
                confidence=0.75,
                severity=Severity.WARNING,
                explanation='Contact or address profile changed since the recent previous scan.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.7,
            severity=Severity.INFO,
            explanation='No suspicious recent contact detail changes were detected.',
            evidence=evidence,
        )

