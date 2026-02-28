from datetime import timedelta
from types import SimpleNamespace

from django.test import TestCase
from django.utils import timezone

from guard.risk_engine.checks.contact_details_change import ContactDetailsChangeCheck


class ContactChangeCheckTests(TestCase):
    def test_flags_recent_contact_profile_change(self):
        previous_scan = SimpleNamespace(
            scanned_at=timezone.now() - timedelta(days=2),
            raw_signals={
                'contact_profile_hash': 'old-contact',
                'address_profile_hash': 'old-address',
            },
        )
        context = SimpleNamespace(site=None, previous_scan=previous_scan, external=SimpleNamespace())
        output = ContactDetailsChangeCheck().run(
            domain='example.com',
            signals={
                'contact_profile_hash': 'new-contact',
                'address_profile_hash': 'new-address',
            },
            context=context,
        )
        self.assertGreater(output.risk_points, 0)

