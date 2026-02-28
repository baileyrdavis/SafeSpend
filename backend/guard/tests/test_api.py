from datetime import datetime, timedelta, timezone
import secrets
from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from guard.models import SeenSite, Site


class ScanApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def scan_payload(self, html_hash='abc123'):
        return {
            'domain': 'https://www.example.com',
            'extension_version': '0.1.0',
            'user_install_hash': 'install-a',
            'extracted_signals': {
                'is_ecommerce': True,
                'is_https': True,
                'currency': 'USD',
                'platform': 'shopify',
                'custom_checkout': False,
                'policies': {
                    'refund': True,
                    'privacy': True,
                    'terms': True,
                },
                'contact': {
                    'email': True,
                    'phone': False,
                    'contact_page': True,
                    'address': False,
                },
                'shipping_destinations': ['US'],
                'html_hash': html_hash,
            },
        }

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_scan_endpoint_returns_risk_payload(self, *_mocks):
        response = self.client.post('/api/scan', self.scan_payload(), format='json')

        self.assertEqual(response.status_code, 200)
        self.assertIn('risk_score', response.data)
        self.assertIn('trust_level', response.data)
        self.assertIn('top_reasons', response.data)
        self.assertEqual(response.data['domain'], 'example.com')
        self.assertFalse(response.data['from_cache'])

        site = Site.objects.get(domain='example.com')
        self.assertIsNotNone(site.last_scanned_at)

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_scan_endpoint_reuses_recent_scan_when_hash_is_same(self, *_mocks):
        first = self.client.post('/api/scan', self.scan_payload('stable-hash'), format='json')
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.data['from_cache'])

        second = self.client.post('/api/scan', self.scan_payload('stable-hash'), format='json')
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.data['from_cache'])
        self.assertEqual(Site.objects.get(domain='example.com').scans.count(), 1)

    @patch('guard.risk_engine.external.has_wayback_history', return_value=False)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=60),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=15),
            'registrar': 'Example Registrar',
        },
    )
    def test_seen_promotion_after_three_unique_install_hashes(self, *_mocks):
        installs = ['install-1', 'install-2', 'install-3']

        for install_hash in installs:
            response = self.client.post(
                '/api/telemetry/seen',
                {
                    'domain': 'promo-test.example',
                    'user_install_hash': install_hash,
                },
                format='json',
            )
            self.assertEqual(response.status_code, 200)

        self.assertTrue(Site.objects.filter(domain='promo-test.example').exists())
        self.assertEqual(SeenSite.objects.filter(domain='promo-test.example', promoted_to_indexed=True).count(), 3)

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_manual_rescan_endpoint_creates_new_scan(self, *_mocks):
        self.client.post('/api/scan', self.scan_payload('hash-a'), format='json')
        before = Site.objects.get(domain='example.com').scans.count()

        response = self.client.post(
            '/api/site/example.com/rescan',
            {
                'extension_version': 'manual',
                'extracted_signals': {'is_ecommerce': True, 'html_hash': 'hash-b'},
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['triggered_by'], 'RECHECK')
        self.assertFalse(response.data['from_cache'])

        after = Site.objects.get(domain='example.com').scans.count()
        self.assertEqual(after, before + 1)

    def test_api_token_required_when_configured(self):
        api_token = secrets.token_urlsafe(24)
        with override_settings(API_AUTH_TOKEN=api_token):
            unauthorized = self.client.get('/api/sites')
            self.assertEqual(unauthorized.status_code, 403)

            authorized = self.client.get('/api/sites', HTTP_X_API_TOKEN=api_token)
            self.assertEqual(authorized.status_code, 200)

    def test_site_list_filters(self):
        Site.objects.create(domain='one.example.com', overall_risk_score=20, trust_level='HIGH')
        Site.objects.create(domain='two.example.com', overall_risk_score=75, trust_level='LOW')

        response = self.client.get('/api/sites?trust_level=LOW&min_risk_score=60')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['domain'], 'two.example.com')

    def test_invalid_domain_rejected(self):
        response = self.client.post(
            '/api/scan',
            {
                'domain': '127.0.0.1',
                'extension_version': '0.1.0',
                'extracted_signals': {'is_ecommerce': True},
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)

    def test_extracted_signals_payload_too_large_rejected(self):
        oversized = {'blob': 'x' * 70000}
        response = self.client.post(
            '/api/scan',
            {
                'domain': 'example.com',
                'extension_version': '0.1.0',
                'extracted_signals': oversized,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_force_private_scan_does_not_persist_site(self, *_mocks):
        payload = self.scan_payload('private-force-hash')
        payload['domain'] = 'force-private.example'
        payload['force_private'] = True
        payload['triggered_by'] = 'MANUAL_LOOKUP'

        response = self.client.post('/api/scan', payload, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['private_result'])
        self.assertFalse(response.data['from_cache'])
        self.assertEqual(response.data['domain'], 'force-private.example')
        self.assertFalse(Site.objects.filter(domain='force-private.example').exists())

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_brand_check_rewards_official_domain(self, *_mocks):
        payload = self.scan_payload('brand-official-hash')
        payload['domain'] = 'target.com.au'
        payload['include_checks'] = True
        payload['extracted_signals']['contact'] = {
            'email': True,
            'phone': False,
            'contact_page': True,
            'address': False,
        }
        payload['extracted_signals']['currency'] = 'AUD'
        payload['extracted_signals']['shipping_destinations'] = ['AU']

        response = self.client.post('/api/scan', payload, format='json')
        self.assertEqual(response.status_code, 200)
        brand_check = next((item for item in response.data['checks'] if item['check_name'] == 'Brand Impersonation Check'), None)
        self.assertIsNotNone(brand_check)
        self.assertEqual(brand_check['risk_points'], -12)

    @patch('guard.risk_engine.external.has_wayback_history', return_value=True)
    @patch('guard.risk_engine.external.get_https_info', return_value={'has_https': True, 'self_signed': False, 'error': None})
    @patch('guard.risk_engine.external.get_nameservers', return_value=['ns1.example.net', 'ns2.example.net'])
    @patch(
        'guard.risk_engine.external.get_whois_data',
        return_value={
            'creation_date': datetime.now(timezone.utc) - timedelta(days=900),
            'updated_date': datetime.now(timezone.utc) - timedelta(days=120),
            'registrar': 'Example Registrar',
        },
    )
    def test_brand_check_penalizes_typosquat_domain(self, *_mocks):
        payload = self.scan_payload('brand-typo-hash')
        payload['domain'] = 't0rget.com.au'
        payload['include_checks'] = True
        payload['extracted_signals']['contact'] = {
            'email': True,
            'phone': False,
            'contact_page': True,
            'address': False,
        }
        payload['extracted_signals']['currency'] = 'AUD'
        payload['extracted_signals']['shipping_destinations'] = ['AU']

        response = self.client.post('/api/scan', payload, format='json')
        self.assertEqual(response.status_code, 200)
        brand_check = next((item for item in response.data['checks'] if item['check_name'] == 'Brand Impersonation Check'), None)
        self.assertIsNotNone(brand_check)
        self.assertEqual(brand_check['risk_points'], 45)
