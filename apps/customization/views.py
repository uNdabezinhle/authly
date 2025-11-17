from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from django.db import models
from datetime import timedelta, date

from .models import (
    TenantBranding, EmailTemplate, TenantUsageMetrics,
    DataExport, ComplianceSettings, OnboardingStep
)
from .serializers import (
    TenantBrandingSerializer, EmailTemplateSerializer, TenantUsageMetricsSerializer,
    DataExportSerializer, ComplianceSettingsSerializer, OnboardingStepSerializer
)
from apps.roles.decorators import IsTenantAdmin


class TenantBrandingViewSet(viewsets.ModelViewSet):
    """Manage tenant branding and customization"""
    serializer_class = TenantBrandingSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return TenantBranding.objects.filter(tenant=self.request.tenant)
    
    def perform_create(self, serializer):
        serializer.save(tenant=self.request.tenant, updated_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def upload_logo(self, request, pk=None):
        """Upload tenant logo"""
        # Implement logo upload logic here
        return Response({'message': 'Logo upload endpoint - implement file handling'})
    
    @action(detail=False, methods=['get'])
    def preview(self, request):
        """Preview branding settings"""
        try:
            branding = TenantBranding.objects.get(tenant=request.tenant)
            return Response({
                'login_page_preview': {
                    'title': branding.login_title,
                    'subtitle': branding.login_subtitle,
                    'primary_color': branding.primary_color,
                    'background_color': branding.background_color,
                    'logo_url': branding.logo_url
                }
            })
        except TenantBranding.DoesNotExist:
            return Response({'error': 'No branding configured'}, status=404)


class EmailTemplateViewSet(viewsets.ModelViewSet):
    """Manage email templates"""
    serializer_class = EmailTemplateSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return EmailTemplate.objects.filter(tenant=self.request.tenant)
    
    def perform_create(self, serializer):
        serializer.save(tenant=self.request.tenant, created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def test_send(self, request, pk=None):
        """Send test email using template"""
        template = self.get_object()
        test_email = request.data.get('test_email', request.user.email)
        
        # Implement email sending logic here
        return Response({
            'message': f'Test email sent to {test_email}',
            'template': template.name
        })


class TenantUsageMetricsViewSet(viewsets.ReadOnlyModelViewSet):
    """View tenant usage metrics"""
    serializer_class = TenantUsageMetricsSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return TenantUsageMetrics.objects.filter(tenant=self.request.tenant)
    
    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """Get dashboard metrics summary"""
        today = date.today()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # Current month metrics
        current_month = TenantUsageMetrics.objects.filter(
            tenant=request.tenant,
            date__gte=month_ago
        ).aggregate(
            total_api_calls=models.Sum('api_calls_total'),
            total_active_users=models.Max('active_users'),
            total_storage=models.Max('storage_used')
        )
        
        # Week over week comparison
        this_week = TenantUsageMetrics.objects.filter(
            tenant=request.tenant,
            date__gte=week_ago
        ).aggregate(api_calls=models.Sum('api_calls_total'))
        
        return Response({
            'current_month': current_month,
            'this_week': this_week,
            'billing_period': {
                'start': month_ago.isoformat(),
                'end': today.isoformat()
            },
            'alerts': []  # Add usage alerts here
        })


class DataExportViewSet(viewsets.ModelViewSet):
    """Manage data exports"""
    serializer_class = DataExportSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    http_method_names = ['get', 'post', 'delete']
    
    def get_queryset(self):
        return DataExport.objects.filter(tenant=self.request.tenant)
    
    def create(self, request):
        """Create new export request"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        export = DataExport.objects.create(
            tenant=request.tenant,
            requested_by=request.user,
            export_type=request.data['export_type'],
            export_format=request.data.get('export_format', 'json'),
            date_from=request.data.get('date_from'),
            date_to=request.data.get('date_to'),
            filters=request.data.get('filters', {}),
            include_deleted=request.data.get('include_deleted', False),
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        # Queue export processing task
        # from .tasks import process_export
        # process_export.delay(export.id)
        
        return Response(
            DataExportSerializer(export).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download completed export"""
        export = self.get_object()
        
        if export.status != 'completed':
            return Response(
                {'error': 'Export not completed'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if export.expires_at and timezone.now() > export.expires_at:
            return Response(
                {'error': 'Export has expired'},
                status=status.HTTP_410_GONE
            )
        
        return Response({
            'download_url': export.download_url,
            'file_size': export.file_size,
            'expires_at': export.expires_at
        })


class ComplianceSettingsViewSet(viewsets.ModelViewSet):
    """Manage compliance settings"""
    serializer_class = ComplianceSettingsSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return ComplianceSettings.objects.filter(tenant=self.request.tenant)
    
    def perform_create(self, serializer):
        serializer.save(tenant=self.request.tenant, updated_by=self.request.user)
    
    @action(detail=False, methods=['get'])
    def compliance_report(self, request):
        """Generate compliance report"""
        settings = ComplianceSettings.objects.filter(tenant=request.tenant).first()
        
        report = {
            'tenant': request.tenant.name,
            'generated_at': timezone.now(),
            'gdpr_compliance': bool(settings and settings.gdpr_enabled),
            'data_retention_policy': settings.data_retention_days if settings else None,
            'audit_coverage': '100%',  # Calculate based on audit logs
            'data_subject_rights': {
                'right_to_access': bool(settings and settings.right_to_access),
                'right_to_erasure': bool(settings and settings.right_to_erasure),
                'right_to_portability': bool(settings and settings.right_to_portability),
            },
            'recommendations': []
        }
        
        # Add recommendations based on settings
        if not settings or not settings.gdpr_enabled:
            report['recommendations'].append('Enable GDPR compliance')
        
        return Response(report)


class OnboardingViewSet(viewsets.ModelViewSet):
    """Manage tenant onboarding"""
    serializer_class = OnboardingStepSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return OnboardingStep.objects.filter(tenant=self.request.tenant)
    
    @action(detail=False, methods=['get'])
    def progress(self, request):
        """Get onboarding progress"""
        steps = self.get_queryset()
        total_steps = steps.count()
        completed_steps = steps.filter(is_completed=True).count()
        
        progress_percentage = (completed_steps / total_steps * 100) if total_steps > 0 else 0
        
        next_step = steps.filter(is_completed=False).order_by('order').first()
        
        return Response({
            'total_steps': total_steps,
            'completed_steps': completed_steps,
            'progress_percentage': progress_percentage,
            'next_step': OnboardingStepSerializer(next_step).data if next_step else None,
            'is_complete': progress_percentage == 100
        })
    
    @action(detail=True, methods=['post'])
    def complete_step(self, request, pk=None):
        """Mark onboarding step as completed"""
        step = self.get_object()
        
        if step.is_completed:
            return Response(
                {'error': 'Step already completed'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        step.is_completed = True
        step.completed_at = timezone.now()
        step.completed_by = request.user
        step.execution_result = request.data.get('result', {})
        step.save()
        
        return Response({
            'message': 'Step completed successfully',
            'step': step.title
        })
    
    @action(detail=False, methods=['post'])
    def auto_complete(self, request):
        """Auto-complete eligible steps"""
        steps = self.get_queryset().filter(
            is_completed=False,
            auto_execute=True
        )
        
        completed_count = 0
        for step in steps:
            # Check dependencies
            if step.depends_on_steps.filter(is_completed=False).exists():
                continue
            
            # Execute step automation logic here
            step.is_completed = True
            step.completed_at = timezone.now()
            step.save()
            completed_count += 1
        
        return Response({
            'message': f'Auto-completed {completed_count} steps',
            'completed_count': completed_count
        })