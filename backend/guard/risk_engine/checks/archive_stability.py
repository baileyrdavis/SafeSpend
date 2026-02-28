from datetime import datetime, timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class ArchiveStabilityCheck(BaseRiskCheck):
    name = 'Archive Stability Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        creation_date = context.external.whois.get('creation_date')
        has_wayback = context.external.has_wayback

        if not creation_date:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='Archive stability could not be fully evaluated.',
                evidence={'has_wayback_history': has_wayback},
            )

        age_days = max((datetime.now(timezone.utc) - creation_date).days, 0)

        if age_days < 365 and not has_wayback:
            return self.output(
                risk_points=15,
                confidence=0.75,
                severity=Severity.WARNING,
                explanation='Newer domain has no public archive history.',
                evidence={
                    'age_days': age_days,
                    'has_wayback_history': has_wayback,
                },
            )

        return self.output(
            risk_points=0,
            confidence=0.65,
            severity=Severity.INFO,
            explanation='Archive history is present or domain age reduces concern.',
            evidence={
                'age_days': age_days,
                'has_wayback_history': has_wayback,
            },
        )