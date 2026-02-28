from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class ContactInformationCheck(BaseRiskCheck):
    name = 'Contact Information Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        contact = signals.get('contact') or {}

        has_contact = any(
            bool(contact.get(field))
            for field in ('email', 'phone', 'contact_page', 'address')
        )

        if not has_contact:
            return self.output(
                risk_points=25,
                confidence=0.9,
                severity=Severity.HIGH,
                explanation='No obvious contact method was detected.',
                evidence={'contact': contact},
            )

        return self.output(
            risk_points=0,
            confidence=0.8,
            severity=Severity.INFO,
            explanation='At least one contact method was detected.',
            evidence={'contact': contact},
        )