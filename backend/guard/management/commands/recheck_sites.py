from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from guard.models import Site, SiteType, TriggeredBy
from guard.services import run_and_persist_scan


class Command(BaseCommand):
    help = 'Re-scan stale indexed sites.'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=7, help='Re-scan sites older than N days.')
        parser.add_argument('--limit', type=int, default=200, help='Maximum number of sites to process.')
        parser.add_argument('--domain', type=str, default='', help='Only process one specific domain.')
        parser.add_argument('--dry-run', action='store_true', help='Print sites that would be scanned.')

    def handle(self, *args, **options):
        days = max(options['days'], 1)
        limit = max(options['limit'], 1)
        target_domain = (options['domain'] or '').strip().lower()
        dry_run = bool(options['dry_run'])

        cutoff = timezone.now() - timedelta(days=days)
        queryset = Site.objects.filter(Q(last_scanned_at__isnull=True) | Q(last_scanned_at__lt=cutoff))

        if target_domain:
            queryset = queryset.filter(domain=target_domain)

        stale_sites = list(queryset.order_by('last_scanned_at', 'domain')[:limit])
        if not stale_sites:
            self.stdout.write(self.style.SUCCESS('No stale sites found.'))
            return

        scanned = 0
        for site in stale_sites:
            if dry_run:
                self.stdout.write(f'[DRY RUN] Would scan: {site.domain}')
                continue

            default_signals = {
                'is_ecommerce': site.site_type == SiteType.ECOM,
                'recheck_command': True,
            }
            run_and_persist_scan(
                site=site,
                domain=site.domain,
                signals=default_signals,
                extension_version='recheck-command',
                triggered_by=TriggeredBy.RECHECK,
            )
            scanned += 1
            self.stdout.write(f'Scanned: {site.domain}')

        if dry_run:
            self.stdout.write(self.style.SUCCESS(f'Dry run complete. {len(stale_sites)} sites matched.'))
            return

        self.stdout.write(self.style.SUCCESS(f'Recheck complete. Scanned {scanned} site(s).'))
