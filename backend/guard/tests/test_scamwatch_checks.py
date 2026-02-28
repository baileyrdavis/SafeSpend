from types import SimpleNamespace

from django.test import TestCase

from guard.risk_engine.checks.abn_validation import AbnValidationCheck
from guard.risk_engine.checks.payment_method_risk import PaymentMethodRiskCheck


def _context():
    return SimpleNamespace(site=None, previous_scan=None, external=SimpleNamespace(au_domain_eligibility={}))


class ScamwatchAlignedChecksTests(TestCase):
    def test_abn_check_skips_non_au_domain_even_with_candidates(self):
        check = AbnValidationCheck()
        output = check.run(
            domain='alibaba.com',
            signals={
                'currency': 'AUD',
                'shipping_destinations': ['AU'],
                'abn_signals': {'candidates': ['51824753556']},
            },
            context=_context(),
        )
        self.assertEqual(output.risk_points, 0)

    def test_abn_check_penalizes_invalid_abn_candidates(self):
        check = AbnValidationCheck()
        output = check.run(
            domain='example.com.au',
            signals={
                'currency': 'AUD',
                'abn_signals': {'candidates': ['12345678901']},
            },
            context=_context(),
        )
        self.assertGreater(output.risk_points, 0)

    def test_abn_check_rewards_valid_abn_candidate(self):
        check = AbnValidationCheck()
        output = check.run(
            domain='example.com.au',
            signals={
                'currency': 'AUD',
                'abn_signals': {'candidates': ['51824753556']},
            },
            context=_context(),
        )
        self.assertLess(output.risk_points, 0)

    def test_payment_method_check_penalizes_risky_method(self):
        check = PaymentMethodRiskCheck()
        output = check.run(
            domain='example.com',
            signals={
                'payment_methods': {
                    'methods': ['gift_card'],
                    'risky_methods': ['gift_card'],
                    'risky_confidence': 0.8,
                    'risky_evidence_count': 1,
                }
            },
            context=_context(),
        )
        self.assertGreater(output.risk_points, 0)

    def test_payment_method_check_rewards_trusted_method(self):
        check = PaymentMethodRiskCheck()
        output = check.run(
            domain='example.com',
            signals={'payment_methods': {'methods': ['paypal', 'stripe']}},
            context=_context(),
        )
        self.assertLess(output.risk_points, 0)

    def test_payment_method_check_does_not_penalize_low_confidence_risky_signal(self):
        check = PaymentMethodRiskCheck()
        output = check.run(
            domain='example.com',
            signals={
                'payment_methods': {
                    'methods': ['crypto'],
                    'risky_methods': ['crypto'],
                    'risky_confidence': 0.2,
                    'risky_evidence_count': 0,
                }
            },
            context=_context(),
        )
        self.assertEqual(output.risk_points, 0)

    def test_abn_check_rewards_when_domain_abn_matches(self):
        check = AbnValidationCheck()
        context = SimpleNamespace(
            site=None,
            previous_scan=None,
            external=SimpleNamespace(au_domain_eligibility={'eligibility_id': '51824753556', 'eligibility_type': 'ABN'}),
        )
        output = check.run(
            domain='example.com.au',
            signals={
                'currency': 'AUD',
                'abn_signals': {'candidates': ['51824753556']},
            },
            context=context,
        )
        self.assertLess(output.risk_points, 0)

    def test_abn_check_penalizes_when_domain_abn_mismatches(self):
        check = AbnValidationCheck()
        context = SimpleNamespace(
            site=None,
            previous_scan=None,
            external=SimpleNamespace(au_domain_eligibility={'eligibility_id': '51824753556', 'eligibility_type': 'ABN'}),
        )
        output = check.run(
            domain='example.com.au',
            signals={
                'currency': 'AUD',
                'abn_signals': {'candidates': ['12345678901']},
            },
            context=context,
        )
        self.assertGreater(output.risk_points, 0)
