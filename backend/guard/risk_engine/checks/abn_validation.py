from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


ABN_WEIGHTS = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]


def is_valid_abn(value: str) -> bool:
    digits = ''.join(ch for ch in str(value or '') if ch.isdigit())
    if len(digits) != 11:
        return False

    numbers = [int(ch) for ch in digits]
    numbers[0] = numbers[0] - 1
    checksum = sum(num * weight for num, weight in zip(numbers, ABN_WEIGHTS))
    return checksum % 89 == 0


def _is_au_context(domain: str, signals: dict) -> bool:
    # Restrict ABN validation to AU-registered domains to avoid false positives
    # on global storefronts that list AU shipping/currency.
    return str(domain or '').lower().endswith('.au')


class AbnValidationCheck(BaseRiskCheck):
    name = 'ABN Validation Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        abn_signals = signals.get('abn_signals') or {}
        candidates = [
            ''.join(ch for ch in str(item or '') if ch.isdigit())
            for item in (abn_signals.get('candidates') or [])
        ]
        candidates = [item for item in candidates if len(item) == 11][:5]
        valid_candidates = [item for item in candidates if is_valid_abn(item)]
        au_context = _is_au_context(domain, signals)
        eligibility = context.external.au_domain_eligibility if au_context else {}
        eligibility_id = ''.join(ch for ch in str(eligibility.get('eligibility_id') or '') if ch.isdigit())
        domain_abn = eligibility_id if len(eligibility_id) == 11 else ''
        domain_abn_matches = bool(domain_abn and domain_abn in candidates)

        evidence = {
            'au_context': au_context,
            'candidate_count': len(candidates),
            'candidates': candidates,
            'valid_candidates': valid_candidates,
            'domain_eligibility_abn': domain_abn,
            'domain_abn_match': domain_abn_matches,
            'domain_eligibility_type': str(eligibility.get('eligibility_type') or ''),
        }

        if not au_context:
            return self.output(
                risk_points=0,
                confidence=0.8,
                severity=Severity.INFO,
                explanation='ABN validation skipped because this is not an AU domain.',
                evidence=evidence,
            )

        if domain_abn and candidates and not domain_abn_matches:
            return self.output(
                risk_points=28,
                confidence=0.88,
                severity=Severity.HIGH,
                explanation='Displayed ABN does not match the ABN associated with this .au domain registration.',
                evidence=evidence,
            )

        if domain_abn and domain_abn_matches:
            return self.output(
                risk_points=-10,
                confidence=0.9,
                severity=Severity.INFO,
                explanation='Displayed ABN matches the ABN associated with this .au domain registration.',
                evidence=evidence,
            )

        if au_context and not candidates:
            return self.output(
                risk_points=10,
                confidence=0.65,
                severity=Severity.WARNING,
                explanation='No ABN was detected on an AU-context storefront.',
                evidence=evidence,
            )

        if candidates and not valid_candidates:
            return self.output(
                risk_points=20,
                confidence=0.8,
                severity=Severity.HIGH,
                explanation='ABN-like numbers were detected but failed checksum validation.',
                evidence=evidence,
            )

        if valid_candidates:
            return self.output(
                risk_points=-6 if au_context else -2,
                confidence=0.8,
                severity=Severity.INFO,
                explanation='At least one ABN candidate passed checksum validation.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.5,
            severity=Severity.INFO,
            explanation='ABN validation was inconclusive.',
            evidence=evidence,
        )
