from __future__ import annotations

from datetime import timedelta
import hashlib
from typing import Any

from django.db import transaction
from django.utils import timezone

from guard.models import CheckResult, EvidenceSnapshot, Scan, SeenSite, Site, SiteType, SnapshotType, TrustLevel
from guard.risk_engine.engine import RiskEngine


DISCLAIMER_TEXT = 'Risk score is informational only.'


def trust_level_from_score(score: int) -> str:
    if score <= 20:
        return TrustLevel.HIGH
    if score <= 50:
        return TrustLevel.MEDIUM
    return TrustLevel.LOW


def should_rescan(site: Site, latest_scan: Scan | None, current_hash: str | None) -> bool:
    if latest_scan is None:
        return True

    if not site.last_scanned_at:
        return True

    if site.last_scanned_at <= timezone.now() - timedelta(days=7):
        return True

    previous_hash = (latest_scan.raw_signals or {}).get('html_hash')
    if current_hash and previous_hash and current_hash != previous_hash:
        return True

    return False


def build_scan_response(scan: Scan) -> dict[str, Any]:
    check_results = list(scan.check_results.all().order_by('-risk_points'))
    top_reasons = [
        {
            'check_name': item.check_name,
            'risk_points': item.risk_points,
            'severity': item.severity,
            'explanation': item.explanation,
            'evidence': item.evidence,
        }
        for item in check_results
        if item.risk_points > 0
    ][:3]

    full_breakdown = [
        {
            'check_name': item.check_name,
            'risk_points': item.risk_points,
            'confidence': item.confidence,
            'severity': item.severity,
            'explanation': item.explanation,
            'evidence': item.evidence,
        }
        for item in check_results
    ]

    return {
        'risk_score': scan.risk_score,
        'trust_level': scan.site.trust_level,
        'top_reasons': top_reasons,
        'checks': full_breakdown,
        'score_confidence': scan.score_confidence,
        'last_scanned_at': scan.scanned_at,
        'disclaimer': DISCLAIMER_TEXT,
    }


def _hash_install_identifier(user_install_hash: str) -> str:
    return hashlib.sha256(user_install_hash.encode('utf-8')).hexdigest()


def _update_site_type(site: Site, signals: dict[str, Any]) -> None:
    if signals.get('is_ecommerce'):
        site.site_type = SiteType.ECOM
    elif not site.site_type:
        site.site_type = SiteType.UNKNOWN


def run_and_persist_scan(
    site: Site,
    domain: str,
    signals: dict[str, Any],
    extension_version: str,
    triggered_by: str,
) -> Scan:
    previous_scan = site.scans.order_by('-scanned_at').first()

    engine = RiskEngine(site=site, previous_scan=previous_scan)
    result = engine.run(domain=domain, signals=signals)

    persisted_signals = dict(signals)
    persisted_signals['extension_version'] = extension_version
    persisted_signals.update(result.enriched_signals)

    with transaction.atomic():
        scan = Scan.objects.create(
            site=site,
            risk_score=result.risk_score,
            score_confidence=result.score_confidence,
            triggered_by=triggered_by,
            raw_signals=persisted_signals,
        )

        CheckResult.objects.bulk_create(
            [
                CheckResult(
                    scan=scan,
                    check_name=check.check_name,
                    risk_points=check.risk_points,
                    confidence=check.confidence,
                    severity=check.severity,
                    explanation=check.explanation,
                    evidence=check.evidence,
                )
                for check in result.checks
            ],
        )

        html_hash = signals.get('html_hash')
        if html_hash:
            EvidenceSnapshot.objects.create(
                site=site,
                snapshot_type=SnapshotType.HTML_HASH,
                content_hash=html_hash,
                metadata={
                    'source': 'extension',
                },
            )

        site.last_scanned_at = timezone.now()
        site.last_seen_at = timezone.now()
        site.overall_risk_score = result.risk_score
        site.trust_level = trust_level_from_score(result.risk_score)
        site.scan_version = engine.version
        _update_site_type(site, signals)
        site.primary_country_guess = result.primary_country_guess
        site.country_confidence = result.country_confidence
        site.save(
            update_fields=[
                'last_scanned_at',
                'last_seen_at',
                'overall_risk_score',
                'trust_level',
                'scan_version',
                'site_type',
                'primary_country_guess',
                'country_confidence',
            ],
        )

    scan.refresh_from_db()
    return scan


def record_seen_domain(domain: str, user_install_hash: str) -> tuple[SeenSite, bool]:
    install_hash = _hash_install_identifier(user_install_hash)
    seen, _ = SeenSite.objects.get_or_create(
        domain=domain,
        user_install_hash=install_hash,
    )

    unique_count = (
        SeenSite.objects.filter(domain=domain)
        .values('user_install_hash')
        .distinct()
        .count()
    )

    promoted = False
    if unique_count >= 3:
        site, created = Site.objects.get_or_create(domain=domain)
        if created or not site.last_scanned_at:
            run_and_persist_scan(
                site=site,
                domain=domain,
                signals={'promotion_trigger': True, 'is_ecommerce': True},
                extension_version='promotion-auto',
                triggered_by='RECHECK',
            )

        SeenSite.objects.filter(domain=domain, promoted_to_indexed=False).update(promoted_to_indexed=True)
        promoted = True

    return seen, promoted
