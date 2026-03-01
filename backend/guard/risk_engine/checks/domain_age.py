from datetime import datetime, timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class DomainAgeCheck(BaseRiskCheck):
    name = 'Domain Age Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        creation_date = context.external.whois.get('creation_date')
        if creation_date is None:
            return self.output(
                risk_points=0,
                confidence=0.3,
                severity=Severity.INFO,
                explanation='Domain age could not be verified from WHOIS data.',
                evidence={},
            )

        now = datetime.now(timezone.utc)
        age_days = max((now - creation_date).days, 0)

        if age_days < 183:
            return self.output(
                risk_points=25,
                confidence=0.9,
                severity=Severity.HIGH,
                explanation='Domain appears to be less than 6 months old.',
                evidence={'age_days': age_days, 'creation_date': creation_date.isoformat()},
            )

        if age_days < 365:
            return self.output(
                risk_points=15,
                confidence=0.85,
                severity=Severity.WARNING,
                explanation='Domain appears between 6 and 12 months old.',
                evidence={'age_days': age_days, 'creation_date': creation_date.isoformat()},
            )

        if age_days > 730:
            return self.output(
                risk_points=0,
                confidence=0.8,
                severity=Severity.INFO,
                explanation='Domain appears older than 2 years, which is not sufficient as a standalone trust reduction.',
                evidence={'age_days': age_days, 'creation_date': creation_date.isoformat()},
            )

        return self.output(
            risk_points=0,
            confidence=0.75,
            severity=Severity.INFO,
            explanation='Domain age is between 1 and 2 years.',
            evidence={'age_days': age_days, 'creation_date': creation_date.isoformat()},
        )
