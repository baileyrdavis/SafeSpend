from datetime import timedelta

from django.utils import timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class DnsChangeCheck(BaseRiskCheck):
    name = 'DNS Change Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        current_nameservers = sorted(context.external.nameservers)
        previous_scan = context.previous_scan

        if not previous_scan:
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='No previous scan available for DNS comparison.',
                evidence={'current_nameservers': current_nameservers},
            )

        previous_nameservers = sorted((previous_scan.raw_signals or {}).get('_nameservers', []))
        if not previous_nameservers or not current_nameservers:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='Nameserver comparison could not be completed.',
                evidence={
                    'current_nameservers': current_nameservers,
                    'previous_nameservers': previous_nameservers,
                },
            )

        if current_nameservers != previous_nameservers and previous_scan.scanned_at >= timezone.now() - timedelta(days=30):
            return self.output(
                risk_points=15,
                confidence=0.8,
                severity=Severity.WARNING,
                explanation='Nameserver records changed within the last 30 days.',
                evidence={
                    'current_nameservers': current_nameservers,
                    'previous_nameservers': previous_nameservers,
                },
            )

        return self.output(
            risk_points=0,
            confidence=0.75,
            severity=Severity.INFO,
            explanation='No risky recent nameserver changes were detected.',
            evidence={
                'current_nameservers': current_nameservers,
                'previous_nameservers': previous_nameservers,
            },
        )