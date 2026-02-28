from guard.brand_intel import find_brand_match, find_typosquat_match
from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class BrandImpersonationCheck(BaseRiskCheck):
    name = 'Brand Impersonation Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        exact = find_brand_match(domain)
        if exact:
            official_domain, brand_name = exact
            return self.output(
                risk_points=-12,
                confidence=0.95,
                severity=Severity.INFO,
                explanation=f'Domain matches an official {brand_name} domain.',
                evidence={
                    'brand_name': brand_name,
                    'matched_domain': official_domain,
                    'match_type': 'exact',
                },
            )

        typosquat = find_typosquat_match(domain)
        if typosquat:
            official_domain, brand_name = typosquat
            return self.output(
                risk_points=45,
                confidence=0.94,
                severity=Severity.HIGH,
                explanation=f'Domain closely resembles official {brand_name} domain {official_domain}.',
                evidence={
                    'brand_name': brand_name,
                    'matched_domain': official_domain,
                    'match_type': 'typosquat-suspected',
                },
            )

        return self.output(
            risk_points=0,
            confidence=0.6,
            severity=Severity.INFO,
            explanation='No strong brand impersonation signals were detected.',
            evidence={'match_type': 'none'},
        )

