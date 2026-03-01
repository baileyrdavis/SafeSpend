from guard.models import Severity
from guard.risk_engine.checks.base import BaseRiskCheck


class HttpsCheck(BaseRiskCheck):
    name = 'HTTPS Check'
    scope = 'GLOBAL'
    version = 1

    def run(self, domain, signals, context):
        is_https = bool(signals.get('is_https', True))
        https_info = context.external.https_info
        mixed_content = signals.get('mixed_content') or {}
        mixed_content_suspected = bool(mixed_content.get('suspected'))
        mixed_content_count = int(mixed_content.get('http_resource_count') or 0)
        https_error = str(https_info.get('error') or '')
        https_error_lower = https_error.lower()

        if not is_https:
            return self.output(
                risk_points=50,
                confidence=0.95,
                severity=Severity.HIGH,
                explanation='Site appears to be served without HTTPS.',
                evidence={'is_https': is_https, 'mixed_content_suspected': mixed_content_suspected},
            )

        if any(token in https_error_lower for token in ['certificate verify failed', 'certificate_verify_failed', 'self signed certificate', 'expired']):
            return self.output(
                risk_points=55,
                confidence=0.92,
                severity=Severity.HIGH,
                explanation='TLS certificate validation failed (expired, self-signed, or untrusted certificate).',
                evidence={'error': https_error, 'mixed_content_suspected': mixed_content_suspected},
            )

        if not https_info.get('has_https'):
            return self.output(
                risk_points=40,
                confidence=0.76,
                severity=Severity.HIGH,
                explanation='HTTPS endpoint could not be verified.',
                evidence={'error': https_info.get('error'), 'mixed_content_suspected': mixed_content_suspected},
            )

        if https_info.get('self_signed'):
            return self.output(
                risk_points=50,
                confidence=0.88,
                severity=Severity.HIGH,
                explanation='HTTPS certificate appears self-signed.',
                evidence={'self_signed': True, 'mixed_content_suspected': mixed_content_suspected},
            )

        if mixed_content_suspected:
            return self.output(
                risk_points=28,
                confidence=0.86,
                severity=Severity.WARNING,
                explanation='HTTPS page appears to include insecure HTTP subresources (mixed content).',
                evidence={
                    'http_resource_count': mixed_content_count,
                    'sample_resources': list(mixed_content.get('sample_resources') or [])[:5],
                },
            )

        return self.output(
            risk_points=0,
            confidence=0.9,
            severity=Severity.INFO,
            explanation='HTTPS appears valid.',
            evidence={'mixed_content_suspected': mixed_content_suspected},
        )
