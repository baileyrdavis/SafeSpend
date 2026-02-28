from unittest.mock import patch

from django.test import TestCase

from guard.sitewide_signals import merge_with_sitewide_signals


class SitewideSignalMergeTests(TestCase):
    @patch('guard.sitewide_signals.collect_sitewide_signals')
    def test_merge_enriches_policy_contact_and_payment_signals(self, mock_collect):
        mock_collect.return_value = {
            'pages_scanned': ['https://example.com/', 'https://example.com/contact'],
            'page_count': 2,
            'policies': {'refund': True, 'privacy': True, 'terms': True},
            'contact': {'email': True, 'phone': False, 'contact_page': True, 'address': True},
            'payment_methods': {
                'methods': ['paypal', 'stripe'],
                'trusted_methods': ['paypal', 'stripe'],
                'risky_methods': [],
                'risky_confidence': 0.0,
                'risky_evidence_count': 0,
                'risky_evidence': [],
            },
            'payment_form_security': {
                'has_raw_card_form_fields': False,
                'card_field_count': 0,
                'expiry_field_count': 0,
                'cvv_field_count': 0,
                'card_form_signal_count': 0,
                'secure_provider_detected': True,
                'secure_provider_iframe_count': 0,
                'secure_provider_script_count': 1,
                'secure_provider_action_count': 0,
                'trusted_providers': ['stripe'],
                'raw_card_form_risk': False,
                'evidence': [],
            },
            'abn_signals': {
                'candidates': ['87692636918'],
                'labeled_candidates': ['87692636918'],
                'unlabeled_candidates': [],
                'candidate_count': 1,
                'labeled_candidate_count': 1,
            },
            'shipping_destinations': ['AU'],
            'currency': 'AUD',
            'dom_features': {
                'checkout_route': True,
                'cart_route': True,
                'checkout_ui_markers': True,
            },
        }

        merged = merge_with_sitewide_signals(
            domain='example.com',
            extracted_signals={
                'policies': {'refund': False, 'privacy': False, 'terms': False},
                'contact': {'email': False, 'phone': False, 'contact_page': False, 'address': False},
                'payment_methods': {'methods': [], 'trusted_methods': [], 'risky_methods': []},
                'payment_form_security': {'has_raw_card_form_fields': False},
                'abn_signals': {'candidates': []},
                'currency': '',
                'shipping_destinations': [],
            },
        )

        self.assertTrue(merged['policies']['privacy'])
        self.assertTrue(merged['contact']['email'])
        self.assertIn('stripe', merged['payment_form_security']['trusted_providers'])
        self.assertIn('paypal', merged['payment_methods']['trusted_methods'])
        self.assertEqual(merged['currency'], 'AUD')
        self.assertIn('AU', merged['shipping_destinations'])
        self.assertTrue(merged['_sitewide_enrichment']['enabled'])

    @patch('guard.sitewide_signals.collect_sitewide_signals')
    def test_merge_preserves_existing_page_level_high_risk_flags(self, mock_collect):
        mock_collect.return_value = {
            'pages_scanned': ['https://example.com/checkout'],
            'page_count': 1,
            'policies': {'refund': False, 'privacy': False, 'terms': False},
            'contact': {'email': False, 'phone': False, 'contact_page': False, 'address': False},
            'payment_methods': {
                'methods': [],
                'trusted_methods': [],
                'risky_methods': [],
                'risky_confidence': 0.0,
                'risky_evidence_count': 0,
                'risky_evidence': [],
            },
            'payment_form_security': {
                'has_raw_card_form_fields': False,
                'card_field_count': 0,
                'expiry_field_count': 0,
                'cvv_field_count': 0,
                'card_form_signal_count': 0,
                'secure_provider_detected': False,
                'secure_provider_iframe_count': 0,
                'secure_provider_script_count': 0,
                'secure_provider_action_count': 0,
                'trusted_providers': [],
                'raw_card_form_risk': False,
                'evidence': [],
            },
            'abn_signals': {'candidates': [], 'labeled_candidates': [], 'unlabeled_candidates': [], 'candidate_count': 0, 'labeled_candidate_count': 0},
            'shipping_destinations': [],
            'currency': '',
            'dom_features': {'checkout_route': False, 'cart_route': False, 'checkout_ui_markers': False},
        }

        merged = merge_with_sitewide_signals(
            domain='example.com',
            extracted_signals={
                'payment_form_security': {
                    'has_raw_card_form_fields': True,
                    'raw_card_form_risk': True,
                    'card_field_count': 1,
                    'expiry_field_count': 1,
                    'cvv_field_count': 1,
                }
            },
        )

        self.assertTrue(merged['payment_form_security']['has_raw_card_form_fields'])
        self.assertTrue(merged['payment_form_security']['raw_card_form_risk'])
