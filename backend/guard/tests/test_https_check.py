from types import SimpleNamespace

from django.test import TestCase

from guard.models import Severity
from guard.risk_engine.checks.https_check import HttpsCheck


def _ctx(https_info):
    return SimpleNamespace(
        site=None,
        previous_scan=None,
        external=SimpleNamespace(https_info=https_info),
    )


class HttpsCheckTests(TestCase):
    def test_tls_certificate_verify_failure_is_high_risk(self):
        output = HttpsCheck().run(
            domain='expired.badssl.com',
            signals={'is_https': True},
            context=_ctx({'has_https': False, 'self_signed': False, 'error': '[SSL: CERTIFICATE_VERIFY_FAILED]'}),
        )
        self.assertGreaterEqual(output.risk_points, 50)

    def test_mixed_content_signal_is_warning(self):
        output = HttpsCheck().run(
            domain='mixed.badssl.com',
            signals={
                'is_https': True,
                'mixed_content': {
                    'suspected': True,
                    'http_resource_count': 2,
                    'sample_resources': ['http://example.com/a.js'],
                },
            },
            context=_ctx({'has_https': True, 'self_signed': False, 'error': None}),
        )
        self.assertGreater(output.risk_points, 0)
        self.assertEqual(output.severity, Severity.WARNING)
