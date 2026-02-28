from types import SimpleNamespace

from django.test import TestCase

from guard.risk_engine.checks.abn_validation import AbnValidationCheck
from guard.risk_engine.checks.payment_form_security import PaymentFormSecurityCheck
from guard.risk_engine.checks.payment_method_risk import PaymentMethodRiskCheck
from guard.risk_engine.checks.payment_processor_reputation import PaymentProcessorReputationCheck


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

    def test_abn_check_prefers_labeled_candidates_over_unlabeled_noise(self):
        check = AbnValidationCheck()
        context = SimpleNamespace(
            site=None,
            previous_scan=None,
            external=SimpleNamespace(au_domain_eligibility={'eligibility_id': '87692636918', 'eligibility_type': 'ABN'}),
        )
        output = check.run(
            domain='spacetek.com.au',
            signals={
                'abn_signals': {
                    'candidates': ['61054583019', '87692636918'],
                    'labeled_candidates': ['87692636918'],
                    'unlabeled_candidates': ['61054583019'],
                }
            },
            context=context,
        )
        self.assertLess(output.risk_points, 0)

    def test_payment_form_security_check_flags_raw_card_collection(self):
        check = PaymentFormSecurityCheck()
        output = check.run(
            domain='demoblaze.com',
            signals={
                'payment_form_security': {
                    'has_raw_card_form_fields': True,
                    'raw_card_form_risk': True,
                    'secure_provider_detected': False,
                    'card_form_signal_count': 3,
                    'card_field_count': 1,
                    'expiry_field_count': 1,
                    'cvv_field_count': 1,
                }
            },
            context=_context(),
        )
        self.assertGreaterEqual(output.risk_points, 40)

    def test_payment_processor_reputation_penalizes_checkout_without_reputable_provider(self):
        check = PaymentProcessorReputationCheck()
        output = check.run(
            domain='demoblaze.com',
            signals={
                'dom_features': {'checkout_route': True, 'cart_route': True, 'checkout_ui_markers': True},
                'payment_form_security': {
                    'has_raw_card_form_fields': True,
                    'trusted_providers': [],
                },
                'payment_methods': {'trusted_methods': []},
            },
            context=_context(),
        )
        self.assertGreater(output.risk_points, 0)

    def test_payment_processor_reputation_rewards_reputable_provider(self):
        check = PaymentProcessorReputationCheck()
        output = check.run(
            domain='example.com',
            signals={
                'dom_features': {'checkout_route': True},
                'payment_form_security': {
                    'trusted_providers': ['stripe'],
                    'has_raw_card_form_fields': False,
                },
                'payment_methods': {'trusted_methods': ['paypal']},
            },
            context=_context(),
        )
        self.assertLess(output.risk_points, 0)
