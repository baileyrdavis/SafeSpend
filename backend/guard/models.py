import uuid

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class SiteType(models.TextChoices):
    ECOM = 'ECOM', 'E-commerce'
    UNKNOWN = 'UNKNOWN', 'Unknown'


class TrustLevel(models.TextChoices):
    LOW = 'LOW', 'Low'
    MEDIUM = 'MEDIUM', 'Medium'
    HIGH = 'HIGH', 'High'


class TriggeredBy(models.TextChoices):
    USER_VISIT = 'USER_VISIT', 'User Visit'
    MANUAL_LOOKUP = 'MANUAL_LOOKUP', 'Manual Lookup'
    RECHECK = 'RECHECK', 'Recheck'


class Severity(models.TextChoices):
    INFO = 'INFO', 'Info'
    WARNING = 'WARNING', 'Warning'
    HIGH = 'HIGH', 'High'


class SnapshotType(models.TextChoices):
    HTML_HASH = 'HTML_HASH', 'HTML Hash'
    SCREENSHOT = 'SCREENSHOT', 'Screenshot'
    POLICY_EXTRACT = 'POLICY_EXTRACT', 'Policy Extract'


class Site(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    site_type = models.CharField(max_length=16, choices=SiteType.choices, default=SiteType.UNKNOWN)
    primary_country_guess = models.CharField(max_length=8, null=True, blank=True)
    country_confidence = models.FloatField(default=0.0)
    overall_risk_score = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    trust_level = models.CharField(max_length=16, choices=TrustLevel.choices, default=TrustLevel.MEDIUM)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    scan_version = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['domain']

    def __str__(self) -> str:
        return self.domain


class Scan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='scans')
    scanned_at = models.DateTimeField(auto_now_add=True, db_index=True)
    risk_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    score_confidence = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )
    triggered_by = models.CharField(max_length=16, choices=TriggeredBy.choices)
    raw_signals = models.JSONField(default=dict)

    class Meta:
        ordering = ['-scanned_at']

    def __str__(self) -> str:
        return f'{self.site.domain} @ {self.scanned_at.isoformat()}'


class CheckResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='check_results')
    check_name = models.CharField(max_length=128)
    risk_points = models.IntegerField()
    confidence = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )
    severity = models.CharField(max_length=16, choices=Severity.choices)
    explanation = models.TextField()
    evidence = models.JSONField(default=dict)

    class Meta:
        indexes = [
            models.Index(fields=['check_name']),
            models.Index(fields=['severity']),
        ]

    def __str__(self) -> str:
        return f'{self.check_name}: {self.risk_points}'


class EvidenceSnapshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='evidence_snapshots')
    snapshot_type = models.CharField(max_length=32, choices=SnapshotType.choices)
    content_hash = models.CharField(max_length=255)
    stored_at = models.DateTimeField(auto_now_add=True, db_index=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        indexes = [
            models.Index(fields=['snapshot_type']),
        ]


class SeenSite(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(max_length=255, db_index=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    user_install_hash = models.CharField(max_length=128)
    promoted_to_indexed = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['domain', 'user_install_hash'], name='uniq_seen_domain_install'),
        ]
        indexes = [
            models.Index(fields=['domain', 'first_seen_at']),
        ]

    def __str__(self) -> str:
        return f'{self.domain} ({self.user_install_hash})'