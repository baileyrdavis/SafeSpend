from django.contrib import admin
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render
from django.urls import path

from guard.domain_utils import is_likely_valid_domain, normalize_domain
from guard.forms import ManualScanForm
from guard.models import (
    ApiAccessToken,
    ApiRefreshToken,
    CheckResult,
    DeviceAuthSession,
    EvidenceSnapshot,
    Scan,
    SeenSite,
    Site,
    TriggeredBy,
)
from guard.services import run_and_persist_scan


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    change_list_template = 'admin/guard/site/change_list.html'
    list_display = (
        'domain',
        'site_type',
        'overall_risk_score',
        'trust_level',
        'primary_country_guess',
        'last_scanned_at',
    )
    search_fields = ('domain',)

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                'manual-scan/',
                self.admin_site.admin_view(self.manual_scan_view),
                name='guard_site_manual_scan',
            ),
        ]
        return custom_urls + urls

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['manual_scan_url'] = 'manual-scan/'
        return super().changelist_view(request, extra_context=extra_context)

    def manual_scan_view(self, request):
        if not request.user.is_superuser:
            raise PermissionDenied('Only superusers can manually add or rescan domains.')

        form = ManualScanForm(request.POST or None)
        if request.method == 'POST' and form.is_valid():
            normalized_domain = normalize_domain(form.cleaned_data['domain'])
            if not is_likely_valid_domain(normalized_domain):
                form.add_error('domain', 'Enter a valid public domain (for example: example.com).')
            else:
                site, created = Site.objects.get_or_create(domain=normalized_domain)
                signals = {'is_ecommerce': form.cleaned_data['is_ecommerce']}
                try:
                    run_and_persist_scan(
                        site=site,
                        domain=normalized_domain,
                        signals=signals,
                        extension_version='admin-manual',
                        triggered_by=TriggeredBy.MANUAL_LOOKUP,
                    )
                except Exception as exc:
                    self.message_user(
                        request,
                        f'Scan failed for {normalized_domain}: {exc}',
                        level=messages.ERROR,
                    )
                else:
                    action = 'created and scanned' if created else 'rescanned'
                    self.message_user(
                        request,
                        f'{normalized_domain} {action} successfully.',
                        level=messages.SUCCESS,
                    )
                    return redirect('admin:guard_site_changelist')

        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Manual Domain Scan',
            'form': form,
        }
        return render(request, 'admin/guard/manual_scan.html', context)


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


@admin.register(DeviceAuthSession)
class DeviceAuthSessionAdmin(admin.ModelAdmin):
    list_display = (
        'user_code',
        'install_hash',
        'status',
        'created_at',
        'expires_at',
        'approved_by',
        'consumed_at',
    )
    list_filter = ('status',)
    search_fields = ('user_code', 'install_hash')
    readonly_fields = (
        'device_code_hash',
        'user_code',
        'install_hash',
        'created_at',
        'approved_at',
        'consumed_at',
        'approved_by',
    )


@admin.register(ApiAccessToken)
class ApiAccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'install_hash', 'issued_at', 'expires_at', 'revoked_at', 'last_used_at')
    list_filter = ('revoked_at',)
    search_fields = ('user__email', 'install_hash')
    readonly_fields = (
        'token_hash',
        'user',
        'install_hash',
        'issued_at',
        'expires_at',
        'revoked_at',
        'last_used_at',
        'created_from_device',
    )


@admin.register(ApiRefreshToken)
class ApiRefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'install_hash', 'issued_at', 'expires_at', 'revoked_at', 'replaced_by')
    list_filter = ('revoked_at',)
    search_fields = ('user__email', 'install_hash')
    readonly_fields = (
        'token_hash',
        'user',
        'install_hash',
        'issued_at',
        'expires_at',
        'revoked_at',
        'replaced_by',
        'access_token',
        'created_from_device',
    )
