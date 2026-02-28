import json

from rest_framework import serializers

from guard.domain_utils import is_likely_valid_domain, normalize_domain
from guard.models import CheckResult, Scan, SeenSite, Site, TriggeredBy


class ScanRequestSerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=255)
    extracted_signals = serializers.JSONField(required=False, default=dict)
    extension_version = serializers.CharField(max_length=32, required=False, allow_blank=True)
    user_install_hash = serializers.CharField(max_length=128, required=False, allow_blank=True)
    triggered_by = serializers.ChoiceField(
        choices=TriggeredBy.choices,
        required=False,
        default=TriggeredBy.USER_VISIT,
    )

    def validate_domain(self, value: str) -> str:
        normalized = normalize_domain(value)
        if not is_likely_valid_domain(normalized):
            raise serializers.ValidationError('A valid domain is required.')
        return normalized

    def validate_extracted_signals(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError('extracted_signals must be an object.')
        if len(value) > 100:
            raise serializers.ValidationError('extracted_signals has too many keys.')
        serialized = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
        if len(serialized.encode('utf-8')) > 65536:
            raise serializers.ValidationError('extracted_signals payload is too large.')
        return value


class CheckResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckResult
        fields = [
            'check_name',
            'risk_points',
            'confidence',
            'severity',
            'explanation',
            'evidence',
        ]


class ScanSerializer(serializers.ModelSerializer):
    check_results = CheckResultSerializer(many=True)

    class Meta:
        model = Scan
        fields = [
            'id',
            'scanned_at',
            'risk_score',
            'score_confidence',
            'triggered_by',
            'check_results',
            'raw_signals',
        ]


class SiteDetailSerializer(serializers.ModelSerializer):
    latest_scan = serializers.SerializerMethodField()

    class Meta:
        model = Site
        fields = [
            'id',
            'domain',
            'first_seen_at',
            'last_seen_at',
            'site_type',
            'primary_country_guess',
            'country_confidence',
            'overall_risk_score',
            'trust_level',
            'last_scanned_at',
            'scan_version',
            'latest_scan',
        ]

    def get_latest_scan(self, obj: Site):
        latest_scan = obj.scans.prefetch_related('check_results').order_by('-scanned_at').first()
        if not latest_scan:
            return None
        return ScanSerializer(latest_scan).data


class SiteListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = [
            'domain',
            'overall_risk_score',
            'trust_level',
            'last_scanned_at',
            'primary_country_guess',
            'country_confidence',
        ]


class SeenTelemetrySerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=255)
    user_install_hash = serializers.CharField(max_length=128)

    def validate_domain(self, value: str) -> str:
        normalized = normalize_domain(value)
        if not is_likely_valid_domain(normalized):
            raise serializers.ValidationError('A valid domain is required.')
        return normalized


class RescanRequestSerializer(serializers.Serializer):
    extracted_signals = serializers.JSONField(required=False, default=dict)
    extension_version = serializers.CharField(max_length=32, required=False, allow_blank=True, default='portal')

    def validate_extracted_signals(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError('extracted_signals must be an object.')
        serialized = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
        if len(serialized.encode('utf-8')) > 65536:
            raise serializers.ValidationError('extracted_signals payload is too large.')
        return value


class SeenSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = SeenSite
        fields = ['domain', 'first_seen_at', 'user_install_hash', 'promoted_to_indexed']
