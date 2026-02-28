from django.conf import settings
from django.http import Http404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from guard.auth import ApiTokenPermission
from guard.domain_utils import normalize_domain
from guard.models import SeenSite, Site, SiteType, TriggeredBy
from guard.serializers import (
    RescanRequestSerializer,
    ScanRequestSerializer,
    SeenTelemetrySerializer,
    SiteDetailSerializer,
    SiteListSerializer,
)
from guard.services import (
    build_scan_response,
    record_seen_domain,
    run_and_persist_scan,
    should_rescan,
)


class HealthAPIView(APIView):
    throttle_scope = 'default'
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({'status': 'ok', 'timestamp': timezone.now(), 'version': settings.APP_VERSION})


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
        triggered_by = payload.get('triggered_by', TriggeredBy.USER_VISIT)
        user_install_hash = payload.get('user_install_hash') or request.headers.get('X-Install-Hash', '')

        if user_install_hash:
            record_seen_domain(domain=domain, user_install_hash=user_install_hash)

        site, _ = Site.objects.get_or_create(domain=domain)
        site.last_seen_at = timezone.now()
        if extracted_signals.get('is_ecommerce'):
            site.site_type = SiteType.ECOM
        site.save(update_fields=['last_seen_at', 'site_type'])

        latest_scan = site.scans.order_by('-scanned_at').first()
        current_hash = extracted_signals.get('html_hash')
        from_cache = True

        if should_rescan(site, latest_scan, current_hash):
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

        payload = build_scan_response(scan)
        payload['domain'] = domain
        payload['from_cache'] = from_cache
        return Response(payload, status=status.HTTP_200_OK)


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
        unique_install_count = (
            SeenSite.objects.filter(domain=domain)
            .values('user_install_hash')
            .distinct()
            .count()
        )

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
        extension_version = serializer.validated_data.get('extension_version', 'portal')

        if site.site_type == SiteType.ECOM and 'is_ecommerce' not in extracted_signals:
            extracted_signals['is_ecommerce'] = True

        scan = run_and_persist_scan(
            site=site,
            domain=normalized_domain,
            signals=extracted_signals,
            extension_version=extension_version,
            triggered_by=TriggeredBy.RECHECK,
        )

        payload = build_scan_response(scan)
        payload['domain'] = normalized_domain
        payload['from_cache'] = False
        payload['triggered_by'] = TriggeredBy.RECHECK
        return Response(payload, status=status.HTTP_200_OK)
