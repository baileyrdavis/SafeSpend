from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from guard.models import Site, SiteType, TrustLevel


class RecheckSitesCommandTests(TestCase):
    def test_recheck_sites_dry_run_lists_stale_domains(self):
        stale_site = Site.objects.create(
            domain='stale-example.com',
            site_type=SiteType.ECOM,
            trust_level=TrustLevel.MEDIUM,
            last_scanned_at=timezone.now() - timedelta(days=10),
        )
        Site.objects.create(
            domain='fresh-example.com',
            site_type=SiteType.ECOM,
            trust_level=TrustLevel.HIGH,
            last_scanned_at=timezone.now() - timedelta(days=1),
        )

        output = StringIO()
        call_command('recheck_sites', '--days', '7', '--dry-run', stdout=output)
        rendered = output.getvalue()

        self.assertIn('stale-example.com', rendered)
        self.assertNotIn('fresh-example.com', rendered)

        stale_site.refresh_from_db()
        self.assertEqual(stale_site.scans.count(), 0)
