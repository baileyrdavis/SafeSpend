from datetime import datetime, timezone

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class RegistrarChangeCheck(BaseRiskCheck):
    name = 'Registrar Change Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        whois_data = context.external.whois
        current_registrar = (whois_data.get('registrar') or '').strip().lower()
        previous_scan = context.previous_scan

        if not current_registrar:
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='Registrar information was unavailable.',
                evidence={},
            )

        previous_registrar = ''
        if previous_scan:
            previous_registrar = str((previous_scan.raw_signals or {}).get('_whois_registrar') or '').strip().lower()

        if previous_registrar and previous_registrar != current_registrar:
            return self.output(
                risk_points=20,
                confidence=0.85,
                severity=Severity.HIGH,
                explanation='Registrar appears to have changed since the previous scan.',
                evidence={
                    'current_registrar': current_registrar,
                    'previous_registrar': previous_registrar,
                },
            )

        updated_date = whois_data.get('updated_date')
        creation_date = whois_data.get('creation_date')
        if updated_date and creation_date:
            domain_age_days = max((datetime.now(timezone.utc) - creation_date).days, 0)
            update_age_days = max((datetime.now(timezone.utc) - updated_date).days, 0)
            if domain_age_days > 365 and update_age_days <= 90:
                return self.output(
                    risk_points=20,
                    confidence=0.75,
                    severity=Severity.WARNING,
                    explanation='Registrar metadata was updated recently on an older domain.',
                    evidence={
                        'current_registrar': current_registrar,
                        'updated_date': updated_date.isoformat(),
                        'days_since_update': update_age_days,
                    },
                )

        return self.output(
            risk_points=0,
            confidence=0.7,
            severity=Severity.INFO,
            explanation='No recent registrar change signals were detected.',
            evidence={'current_registrar': current_registrar},
        )