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
        if not current_hash or not previous_hash:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='HTML hash comparison was inconclusive.',
                evidence={'current_hash_present': bool(current_hash), 'previous_hash_present': bool(previous_hash)},
            )

        if current_hash != previous_hash and previous_scan.scanned_at >= timezone.now() - timedelta(days=30):
            return self.output(
                risk_points=10,
                confidence=0.75,
                severity=Severity.WARNING,
                explanation='Significant homepage hash delta detected since last scan.',
                evidence={'previous_hash': previous_hash, 'current_hash': current_hash},
            )

        return self.output(
            risk_points=0,
            confidence=0.75,
            severity=Severity.INFO,
            explanation='No suspicious short-term HTML hash change detected.',
            evidence={'previous_hash': previous_hash, 'current_hash': current_hash},
        )