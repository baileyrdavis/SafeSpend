from django.conf import settings

from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class ThreatFeedReputationCheck(BaseRiskCheck):
    name = 'Threat Feed Reputation Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        if not bool(getattr(settings, 'GUARD_ENABLE_THREAT_FEED_CHECK', True)):
            return self.output(
                risk_points=0,
                confidence=0.5,
                severity=Severity.INFO,
                explanation='Threat feed reputation check is disabled by configuration.',
                evidence={'enabled': False},
            )

        reputation = context.external.threat_feed_reputation
        matched = bool(reputation.get('matched'))
        feeds = [str(item) for item in (reputation.get('matched_feeds') or []) if item]
        feed_errors = {
            key: value
            for key, value in dict(reputation.get('feed_errors') or {}).items()
            if value
        }
        feed_counts = dict(reputation.get('feed_counts') or {})

        evidence = {
            'matched': matched,
            'matched_host': str(reputation.get('matched_host') or ''),
            'matched_root_domain': str(reputation.get('matched_root_domain') or ''),
            'matched_feeds': feeds,
            'feed_counts': feed_counts,
            'feed_errors': feed_errors,
        }

        if matched:
            return self.output(
                risk_points=70,
                confidence=0.96,
                severity=Severity.HIGH,
                explanation='Domain appears on public phishing/malware threat feeds.',
                evidence=evidence,
            )

        if feed_errors and not any(int(feed_counts.get(name) or 0) > 0 for name in ('openphish', 'urlhaus_hostfile')):
            return self.output(
                risk_points=0,
                confidence=0.4,
                severity=Severity.INFO,
                explanation='Threat feed reputation check was unavailable.',
                evidence=evidence,
            )

        return self.output(
            risk_points=0,
            confidence=0.78,
            severity=Severity.INFO,
            explanation='No direct matches found in configured public threat feeds.',
            evidence=evidence,
        )
