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


def should_rescan(site: Site, latest_scan: Scan | None, signals: dict[str, Any] | None) -> bool:
    if latest_scan is None:
        return True

    if not site.last_scanned_at:
        return True

    if site.last_scanned_at <= timezone.now() - timedelta(days=7):
        return True

    previous_signals = latest_scan.raw_signals or {}
    current_signals = signals or {}

    # Only trigger short-cycle rescans when stable high-signal fields changed.
    critical_keys = [
        'checkout_domain',
        'contact_profile_hash',
        'address_profile_hash',
        'is_https',
        'custom_checkout',
    ]
    for key in critical_keys:
        previous_value = previous_signals.get(key)
        current_value = current_signals.get(key)
        if current_value is None:
            continue
        if previous_value != current_value:
            return True

    current_hash = current_signals.get('html_hash')
    previous_hash = previous_signals.get('html_hash')
    if (
        current_hash
        and previous_hash
        and current_hash != previous_hash
        and site.last_scanned_at <= timezone.now() - timedelta(days=2)
    ):
        # Hash-only drift can be noisy for active storefronts. Use it as a
        # slower fallback trigger when no critical signal changed.
        return True

    return False


def _serialize_check_result(check: CheckResult, include_evidence: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'check_name': check.check_name,
        'risk_points': check.risk_points,
        'confidence': check.confidence,
        'severity': check.severity,
        'explanation': check.explanation,
    }
    if include_evidence:
        payload['evidence'] = check.evidence
    return payload


def _serialize_engine_check(check, include_evidence: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'check_name': str(getattr(check, 'check_name', 'Unknown check')),
        'risk_points': int(getattr(check, 'risk_points', 0)),
        'confidence': float(getattr(check, 'confidence', 0.0)),
        'severity': str(getattr(check, 'severity', 'INFO')),
        'explanation': str(getattr(check, 'explanation', 'No explanation available.')),
    }
    if include_evidence:
        payload['evidence'] = dict(getattr(check, 'evidence', {}) or {})
    return payload


def build_scan_response(scan: Scan, include_checks: bool = True, include_evidence: bool = True) -> dict[str, Any]:
    check_results = list(scan.check_results.all().order_by('-risk_points'))
    top_reasons = [
        _serialize_check_result(item, include_evidence=include_evidence)
        for item in check_results
        if item.risk_points > 0
    ][:3]
    top_reductions = [
        _serialize_check_result(item, include_evidence=include_evidence)
        for item in sorted(check_results, key=lambda item: item.risk_points)
        if item.risk_points < 0
    ][:3]

    full_breakdown = [_serialize_check_result(item, include_evidence=include_evidence) for item in check_results]

    payload = {
        'risk_score': scan.risk_score,
        'trust_level': scan.site.trust_level,
        'top_reasons': top_reasons,
        'top_reductions': top_reductions,
        'score_confidence': scan.score_confidence,
        'last_scanned_at': scan.scanned_at,
        'disclaimer': DISCLAIMER_TEXT,
    }
    payload['checks'] = full_breakdown if include_checks else []
    return payload


def build_private_scan_response(
    domain: str,
    signals: dict[str, Any],
    include_checks: bool = True,
    include_evidence: bool = True,
) -> dict[str, Any]:
    transient_site = Site(domain=domain)
    engine = RiskEngine(site=transient_site, previous_scan=None)
    result = engine.run(domain=domain, signals=signals)
    trust_level = trust_level_from_score(result.risk_score)

    checks_sorted_desc = sorted(result.checks, key=lambda item: item.risk_points, reverse=True)
    checks_sorted_asc = sorted(result.checks, key=lambda item: item.risk_points)

    top_reasons = [
        _serialize_engine_check(item, include_evidence=include_evidence)
        for item in checks_sorted_desc
        if item.risk_points > 0
    ][:3]
    top_reductions = [
        _serialize_engine_check(item, include_evidence=include_evidence)
        for item in checks_sorted_asc
        if item.risk_points < 0
    ][:3]
    full_breakdown = [_serialize_engine_check(item, include_evidence=include_evidence) for item in checks_sorted_desc]

    payload = {
        'risk_score': result.risk_score,
        'trust_level': trust_level,
        'top_reasons': top_reasons,
        'top_reductions': top_reductions,
        'score_confidence': result.score_confidence,
        'last_scanned_at': timezone.now(),
        'disclaimer': f'{DISCLAIMER_TEXT} Private force-check results are only visible to this signed-in user.',
        'checks': full_breakdown if include_checks else [],
        'private_result': True,
    }
    return payload


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
