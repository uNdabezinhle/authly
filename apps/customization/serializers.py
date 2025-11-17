from rest_framework import serializers
from .models import (
    TenantBranding, EmailTemplate, TenantUsageMetrics, 
    DataExport, ComplianceSettings, OnboardingStep
)


class TenantBrandingSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantBranding
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class EmailTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailTemplate
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class TenantUsageMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantUsageMetrics
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class DataExportSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataExport
        fields = [
            'id', 'export_type', 'export_format', 'requested_at',
            'status', 'progress_percentage', 'file_size',
            'download_url', 'expires_at', 'records_exported'
        ]
        read_only_fields = ['id', 'requested_at', 'download_url']


class ComplianceSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceSettings
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class OnboardingStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnboardingStep
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'completed_at']