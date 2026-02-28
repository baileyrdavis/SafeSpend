from django.contrib import admin

from guard.models import CheckResult, EvidenceSnapshot, Scan, SeenSite, Site


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = (
        'domain',
        'site_type',
        'overall_risk_score',
        'trust_level',
        'primary_country_guess',
        'last_scanned_at',
    )
    search_fields = ('domain',)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('site', 'scanned_at', 'risk_score', 'score_confidence', 'triggered_by')
    list_filter = ('triggered_by',)


@admin.register(CheckResult)
class CheckResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'check_name', 'risk_points', 'severity', 'confidence')
    list_filter = ('severity', 'check_name')


@admin.register(EvidenceSnapshot)
class EvidenceSnapshotAdmin(admin.ModelAdmin):
    list_display = ('site', 'snapshot_type', 'content_hash', 'stored_at')
    list_filter = ('snapshot_type',)


@admin.register(SeenSite)
class SeenSiteAdmin(admin.ModelAdmin):
    list_display = ('domain', 'user_install_hash', 'first_seen_at', 'promoted_to_indexed')
    list_filter = ('promoted_to_indexed',)
    search_fields = ('domain', 'user_install_hash')