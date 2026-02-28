from urllib.parse import urlencode
import logging

from django.conf import settings
from django.db import transaction
from django.http import Http404
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from guard.auth import ApiTokenPermission
from guard.auth_service import (
    AuthServiceError,
    create_device_auth_session,
    delete_user_account,
    exchange_device_code_for_tokens,
    refresh_access_token,
    revoke_install_tokens,
)
from guard.domain_utils import normalize_domain
from guard.models import SeenSite, Site, SiteType, TriggeredBy
from guard.serializers import (
    DeviceAuthPollSerializer,
    DeviceAuthStartSerializer,
    RescanRequestSerializer,
    ScanRequestSerializer,
    SeenTelemetrySerializer,
    SiteDetailSerializer,
    SiteListSerializer,
    TokenRefreshSerializer,
)
from guard.services import build_private_scan_response, build_scan_response, record_seen_domain, run_and_persist_scan, should_rescan

logger = logging.getLogger(__name__)


def _auth_error_response(error: AuthServiceError) -> Response:
    return Response(
        {
            'error': error.code,
            'detail': error.message,
        },
        status=error.http_status,
    )


def _token_response_payload(token_pair) -> dict:
    now = timezone.now()
    access_expires_in = max(int((token_pair.access_token_expires_at - now).total_seconds()), 0)
    refresh_expires_in = max(int((token_pair.refresh_token_expires_at - now).total_seconds()), 0)
    return {
        'token_type': 'Bearer',  # nosec B105
        'access_token': token_pair.access_token,
        'access_token_expires_in': access_expires_in,
        'access_token_expires_at': token_pair.access_token_expires_at,
        'refresh_token': token_pair.refresh_token,
        'refresh_token_expires_in': refresh_expires_in,
        'refresh_token_expires_at': token_pair.refresh_token_expires_at,
    }


class HealthAPIView(APIView):
    throttle_scope = 'default'
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({'status': 'ok', 'timestamp': timezone.now(), 'version': settings.APP_VERSION})


class DeviceAuthStartAPIView(APIView):
    throttle_scope = 'auth_start'
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = DeviceAuthStartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        session, device_code = create_device_auth_session(
            install_hash=serializer.validated_data['install_hash'],
        )
        verification_uri = request.build_absolute_uri(reverse('device-verify'))
        verification_uri_complete = f"{verification_uri}?{urlencode({'user_code': session.user_code})}"
        expires_in = max(int((session.expires_at - timezone.now()).total_seconds()), 0)

        return Response(
            {
                'device_code': device_code,
                'user_code': session.user_code,
                'verification_uri': verification_uri,
                'verification_uri_complete': verification_uri_complete,
                'expires_in': expires_in,
                'interval': session.interval_seconds,
                'disclaimer': 'Risk score is informational only.',
            },
            status=status.HTTP_200_OK,
        )


class DeviceAuthPollAPIView(APIView):
    throttle_scope = 'auth_poll'
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = DeviceAuthPollSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token_pair = exchange_device_code_for_tokens(
                device_code=serializer.validated_data['device_code'],
                install_hash=serializer.validated_data['install_hash'],
            )
        except AuthServiceError as error:
            return _auth_error_response(error)
        except Exception:
            install_hash = serializer.validated_data.get('install_hash', '')
            device_code = serializer.validated_data.get('device_code', '')
            logger.exception(
                'Unexpected device authorization polling failure '
                '(install_hash_len=%s, device_code_len=%s).',
                len(install_hash),
                len(device_code),
            )
            return Response(
                {
                    'error': 'server_error',
                    'detail': 'Authorization service error. Please try again.',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(_token_response_payload(token_pair), status=status.HTTP_200_OK)


class TokenRefreshAPIView(APIView):
    throttle_scope = 'auth_refresh'
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token_pair = refresh_access_token(
                refresh_token=serializer.validated_data['refresh_token'],
                install_hash=serializer.validated_data['install_hash'],
            )
        except AuthServiceError as error:
            return _auth_error_response(error)

        return Response(_token_response_payload(token_pair), status=status.HTTP_200_OK)


class AuthSessionAPIView(APIView):
    throttle_scope = 'default'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def get(self, request):
        access_token = getattr(request, 'guard_access_token', None)
        user = getattr(request, 'guard_user', None)
        auth_mode = getattr(request, 'guard_auth_mode', 'unknown')
        return Response(
            {
                'authenticated': auth_mode in {'access-token', 'static-token'},
                'auth_mode': auth_mode,
                'user': user.email if user else None,
                'access_token_expires_at': access_token.expires_at if access_token else None,
            },
            status=status.HTTP_200_OK,
        )


class LogoutAPIView(APIView):
    throttle_scope = 'auth_refresh'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def post(self, request):
        access_token = getattr(request, 'guard_access_token', None)
        if access_token is None:
            return Response(
                {
                    'detail': 'Logout with static token mode is not supported.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_revoked, refresh_revoked = revoke_install_tokens(
            user_id=access_token.user_id,
            install_hash=access_token.install_hash,
        )
        return Response(
            {
                'ok': True,
                'access_tokens_revoked': access_revoked,
                'refresh_tokens_revoked': refresh_revoked,
            },
            status=status.HTTP_200_OK,
        )


class AccountDeleteAPIView(APIView):
    throttle_scope = 'auth_refresh'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def post(self, request):
        user = getattr(request, 'guard_user', None)
        auth_mode = getattr(request, 'guard_auth_mode', '')
        if user is None or auth_mode != 'access-token':
            return Response(
                {
                    'detail': 'Account deletion requires an authenticated user session.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        confirm_email = str((request.data or {}).get('confirm_email', '')).strip().lower()
        if not confirm_email:
            return Response(
                {
                    'detail': 'confirm_email is required to delete account.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if confirm_email != str(user.email or '').strip().lower():
            return Response(
                {
                    'detail': 'Email confirmation did not match this account.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_superuser:
            return Response(
                {
                    'detail': 'Superuser accounts cannot be deleted via extension API.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        delete_user_account(user_id=user.id)
        return Response({'ok': True}, status=status.HTTP_200_OK)


class ScanAPIView(APIView):
    throttle_scope = 'scan'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        payload = serializer.validated_data
        domain = payload['domain']
        extracted_signals = payload.get('extracted_signals') or {}
        extension_version = payload.get('extension_version', '')
        include_checks = payload.get('include_checks', False)
        include_evidence = payload.get('include_evidence', False)
        force_private = payload.get('force_private', False)
        triggered_by = payload.get('triggered_by', TriggeredBy.USER_VISIT)
        user_install_hash = payload.get('user_install_hash') or request.headers.get('X-Install-Hash', '')

        if force_private:
            response_payload = build_private_scan_response(
                domain=domain,
                signals=extracted_signals,
                include_checks=include_checks,
                include_evidence=include_evidence,
            )
            response_payload['domain'] = domain
            response_payload['from_cache'] = False
            response_payload['triggered_by'] = TriggeredBy.MANUAL_LOOKUP
            return Response(response_payload, status=status.HTTP_200_OK)

        if user_install_hash:
            record_seen_domain(domain=domain, user_install_hash=user_install_hash)

        site, _ = Site.objects.get_or_create(domain=domain)
        site.last_seen_at = timezone.now()
        if extracted_signals.get('is_ecommerce'):
            site.site_type = SiteType.ECOM
        site.save(update_fields=['last_seen_at', 'site_type'])

        from_cache = True

        with transaction.atomic():
            site = Site.objects.select_for_update().get(pk=site.pk)
            latest_scan = site.scans.order_by('-scanned_at').first()

            if should_rescan(site, latest_scan, extracted_signals):
                scan = run_and_persist_scan(
                    site=site,
                    domain=domain,
                    signals=extracted_signals,
                    extension_version=extension_version,
                    triggered_by=triggered_by,
                )
                from_cache = False
            else:
                scan = latest_scan

            if not scan:
                scan = run_and_persist_scan(
                    site=site,
                    domain=domain,
                    signals=extracted_signals,
                    extension_version=extension_version,
                    triggered_by=triggered_by,
                )
                from_cache = False

        response_payload = build_scan_response(
            scan,
            include_checks=include_checks,
            include_evidence=include_evidence,
        )
        response_payload['domain'] = domain
        response_payload['from_cache'] = from_cache
        return Response(response_payload, status=status.HTTP_200_OK)


class SiteDetailAPIView(APIView):
    throttle_scope = 'lookup'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def get(self, request, domain: str):
        normalized_domain = normalize_domain(domain)
        try:
            site = Site.objects.get(domain=normalized_domain)
        except Site.DoesNotExist as exc:
            raise Http404('Site not indexed') from exc

        return Response(SiteDetailSerializer(site).data)


class SiteListAPIView(APIView):
    throttle_scope = 'lookup'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def get(self, request):
        try:
            limit = min(max(int(request.query_params.get('limit', 50)), 1), 200)
        except ValueError:
            limit = 50

        queryset = Site.objects.all()

        trust_level = (request.query_params.get('trust_level') or '').upper()
        if trust_level in {'LOW', 'MEDIUM', 'HIGH'}:
            queryset = queryset.filter(trust_level=trust_level)

        try:
            min_risk_score = int(request.query_params.get('min_risk_score', 0))
            min_risk_score = max(min_risk_score, 0)
            queryset = queryset.filter(overall_risk_score__gte=min_risk_score)
        except ValueError:
            pass

        domain_query = (request.query_params.get('q') or '').strip()
        if domain_query:
            queryset = queryset.filter(domain__icontains=domain_query)

        sites = queryset.order_by('-last_scanned_at', '-overall_risk_score')[:limit]
        return Response({'results': SiteListSerializer(sites, many=True).data})


class SeenTelemetryAPIView(APIView):
    throttle_scope = 'telemetry'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def post(self, request):
        serializer = SeenTelemetrySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        domain = serializer.validated_data['domain']
        user_install_hash = serializer.validated_data['user_install_hash']

        _, promoted = record_seen_domain(domain=domain, user_install_hash=user_install_hash)
        unique_install_count = SeenSite.objects.filter(domain=domain).values('user_install_hash').distinct().count()

        return Response(
            {
                'domain': domain,
                'unique_install_count': unique_install_count,
                'promoted': promoted,
            },
            status=status.HTTP_200_OK,
        )


class SiteRescanAPIView(APIView):
    throttle_scope = 'rescan'
    authentication_classes = []
    permission_classes = [ApiTokenPermission]

    def post(self, request, domain: str):
        normalized_domain = normalize_domain(domain)
        serializer = RescanRequestSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)

        try:
            site = Site.objects.get(domain=normalized_domain)
        except Site.DoesNotExist as exc:
            raise Http404('Site not indexed') from exc

        extracted_signals = serializer.validated_data.get('extracted_signals') or {}
        extension_version = serializer.validated_data.get('extension_version', 'manual')
        include_checks = serializer.validated_data.get('include_checks', True)
        include_evidence = serializer.validated_data.get('include_evidence', True)

        if site.site_type == SiteType.ECOM and 'is_ecommerce' not in extracted_signals:
            extracted_signals['is_ecommerce'] = True

        scan = run_and_persist_scan(
            site=site,
            domain=normalized_domain,
            signals=extracted_signals,
            extension_version=extension_version,
            triggered_by=TriggeredBy.RECHECK,
        )

        response_payload = build_scan_response(scan, include_checks=include_checks, include_evidence=include_evidence)
        response_payload['domain'] = normalized_domain
        response_payload['from_cache'] = False
        response_payload['triggered_by'] = TriggeredBy.RECHECK
        return Response(response_payload, status=status.HTTP_200_OK)
