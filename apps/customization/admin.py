from django.contrib import admin
from .models import (
    TenantBranding, EmailTemplate, TenantUsageMetrics,
    DataExport, ComplianceSettings, OnboardingStep
)


@admin.register(TenantBranding)
class TenantBrandingAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'company_name', 'primary_color', 'updated_at']
    list_filter = ['updated_at']
    search_fields = ['tenant__name', 'company_name']


@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'template_type', 'name', 'is_active', 'is_default']
    list_filter = ['template_type', 'is_active', 'is_default']
    search_fields = ['tenant__name', 'name', 'subject']


@admin.register(TenantUsageMetrics)
class TenantUsageMetricsAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'date', 'hour', 'api_calls_total', 'active_users']
    list_filter = ['date', 'hour']
    search_fields = ['tenant__name']
    readonly_fields = ['created_at']


@admin.register(DataExport)
class DataExportAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'export_type', 'status', 'requested_at', 'file_size']
    list_filter = ['export_type', 'status', 'requested_at']
    search_fields = ['tenant__name', 'requested_by__email']
    readonly_fields = ['requested_at', 'started_at', 'completed_at']


@admin.register(ComplianceSettings)
class ComplianceSettingsAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'gdpr_enabled', 'data_retention_days', 'updated_at']
    list_filter = ['gdpr_enabled', 'automatic_deletion']
    search_fields = ['tenant__name']


@admin.register(OnboardingStep)
class OnboardingStepAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'step_type', 'title', 'order', 'is_completed']
    list_filter = ['step_type', 'is_completed', 'is_required']
    search_fields = ['tenant__name', 'title']