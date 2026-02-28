from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIClient

from guard.auth_service import issue_token_pair


@override_settings(API_REQUIRE_AUTH=True, API_AUTH_TOKEN='')
class DeviceAuthFlowTests(TestCase):
    def setUp(self):
        self.api_client = APIClient()
        self.web_client = Client()
        self.install_hash = '7f8bc45ad2114eca9fc1b165ef909c11'
        self.user = get_user_model().objects.create_user(
            username='consumer',
            email='consumer@example.com',
            password='strong-password',
        )

    def test_device_authorization_flow_can_issue_access_tokens(self):
        start_response = self.api_client.post(
            '/api/auth/device/start',
            {'install_hash': self.install_hash},
            format='json',
        )
        self.assertEqual(start_response.status_code, 200)
        self.assertIn('device_code', start_response.data)
        self.assertIn('user_code', start_response.data)

        pending_response = self.api_client.post(
            '/api/auth/device/poll',
            {
                'device_code': start_response.data['device_code'],
                'install_hash': self.install_hash,
            },
            format='json',
        )
        self.assertEqual(pending_response.status_code, 428)
        self.assertEqual(pending_response.data['error'], 'authorization_pending')

        self.web_client.force_login(self.user)
        approve_response = self.web_client.post(
            '/auth/device/verify',
            {'user_code': start_response.data['user_code']},
        )
        self.assertEqual(approve_response.status_code, 200)
        self.assertContains(approve_response, 'Extension approved')

        poll_response = self.api_client.post(
            '/api/auth/device/poll',
            {
                'device_code': start_response.data['device_code'],
                'install_hash': self.install_hash,
            },
            format='json',
        )
        self.assertEqual(poll_response.status_code, 200)
        self.assertIn('access_token', poll_response.data)
        self.assertIn('refresh_token', poll_response.data)

        protected_response = self.api_client.get(
            '/api/sites',
            HTTP_AUTHORIZATION=f"Bearer {poll_response.data['access_token']}",
        )
        self.assertEqual(protected_response.status_code, 200)

    def test_refresh_rotation_revokes_previous_refresh_token(self):
        token_pair = issue_token_pair(user=self.user, install_hash=self.install_hash)

        refresh_response = self.api_client.post(
            '/api/auth/token/refresh',
            {
                'refresh_token': token_pair.refresh_token,
                'install_hash': self.install_hash,
            },
            format='json',
        )
        self.assertEqual(refresh_response.status_code, 200)
        self.assertIn('access_token', refresh_response.data)
        self.assertIn('refresh_token', refresh_response.data)

        replay_response = self.api_client.post(
            '/api/auth/token/refresh',
            {
                'refresh_token': token_pair.refresh_token,
                'install_hash': self.install_hash,
            },
            format='json',
        )
        self.assertEqual(replay_response.status_code, 401)
        self.assertEqual(replay_response.data['error'], 'invalid_grant')

    def test_logout_revokes_install_token_family(self):
        token_pair = issue_token_pair(user=self.user, install_hash=self.install_hash)

        logout_response = self.api_client.post(
            '/api/auth/logout',
            {},
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}',
        )
        self.assertEqual(logout_response.status_code, 200)
        self.assertTrue(logout_response.data['ok'])

        denied_response = self.api_client.get(
            '/api/sites',
            HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}',
        )
        self.assertEqual(denied_response.status_code, 403)
