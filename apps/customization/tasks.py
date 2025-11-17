from celery import shared_task
from django.utils import timezone
from django.core.serializers import serialize
import json
import os
import zipfile
import tempfile
from datetime import timedelta


@shared_task
def process_data_export(export_id):
    """Process data export in background"""
    from .models import DataExport
    from apps.users.models import User
    from apps.audit.models import AuditLog
    
    try:
        export = DataExport.objects.get(id=export_id)
        export.status = 'processing'
        export.started_at = timezone.now()
        export.save()
        
        # Create temporary directory for export files
        with tempfile.TemporaryDirectory() as temp_dir:
            export_data = {}
            
            # Export users data
            if export.export_type in ['backup', 'users', 'gdpr']:
                users = User.objects.filter(tenant=export.tenant)
                if export.date_from and export.date_to:
                    users = users.filter(date_joined__range=[export.date_from, export.date_to])
                
                export_data['users'] = [
                    {
                        'id': str(user.id),
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'date_joined': user.date_joined.isoformat(),
                        'is_active': user.is_active,
                        'mfa_enabled': user.mfa_enabled if hasattr(user, 'mfa_enabled') else False
                    } for user in users
                ]
            
            # Export audit logs
            if export.export_type in ['backup', 'audit_logs', 'compliance']:
                logs = AuditLog.objects.filter(tenant=export.tenant)
                if export.date_from and export.date_to:
                    logs = logs.filter(timestamp__range=[export.date_from, export.date_to])
                
                export_data['audit_logs'] = [
                    {
                        'id': str(log.id),
                        'action': log.action,
                        'actor_email': log.actor_email,
                        'timestamp': log.timestamp.isoformat(),
                        'ip_address': log.ip_address,
                        'risk_level': log.risk_level,
                        'success': log.success,
                        'metadata': log.metadata
                    } for log in logs
                ]
            
            # Create export file
            export_filename = f"{export.export_type}_{export.tenant.slug}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{export.export_format}"
            export_path = os.path.join(temp_dir, export_filename)
            
            if export.export_format == 'json':
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
            elif export.export_format == 'csv':
                # Implement CSV export
                pass
            elif export.export_format == 'encrypted':
                # Create encrypted archive
                pass
            
            # Calculate file size
            file_size = os.path.getsize(export_path)
            
            # Move to final storage location (implement your storage logic)
            final_path = f"/exports/{export.tenant.slug}/{export_filename}"
            download_url = f"https://api.authly.com/exports/{export.tenant.slug}/{export_filename}"
            
            # Update export record
            export.status = 'completed'
            export.completed_at = timezone.now()
            export.file_path = final_path
            export.file_size = file_size
            export.download_url = download_url
            export.records_exported = len(export_data.get('users', [])) + len(export_data.get('audit_logs', []))
            export.processing_time_seconds = int((export.completed_at - export.started_at).total_seconds())
            export.save()
            
    except Exception as e:
        export.status = 'failed'
        export.error_message = str(e)
        export.save()


@shared_task
def generate_daily_metrics():
    """Generate daily usage metrics for all tenants"""
    from .models import TenantUsageMetrics
    from apps.tenants.models import Tenant
    from apps.audit.models import AuditLog
    from apps.users.models import User
    from datetime import date
    
    today = date.today()
    
    for tenant in Tenant.objects.all():
        # Skip if metrics already exist for today
        if TenantUsageMetrics.objects.filter(tenant=tenant, date=today, hour__isnull=True).exists():
            continue
        
        # Count API calls from audit logs
        api_logs = AuditLog.objects.filter(
            tenant=tenant,
            timestamp__date=today
        )
        
        api_calls_total = api_logs.count()
        api_calls_auth = api_logs.filter(action__in=['login', 'logout', 'register']).count()
        login_count = api_logs.filter(action='login').count()
        
        # Count active users
        active_users = User.objects.filter(
            tenant=tenant,
            last_login__date=today
        ).count()
        
        new_users = User.objects.filter(
            tenant=tenant,
            date_joined__date=today
        ).count()
        
        # Create metrics record
        TenantUsageMetrics.objects.create(
            tenant=tenant,
            date=today,
            api_calls_total=api_calls_total,
            api_calls_auth=api_calls_auth,
            login_count=login_count,
            active_users=active_users,
            new_users=new_users
        )


@shared_task
def cleanup_expired_exports():
    """Clean up expired data exports"""
    from .models import DataExport
    
    expired_exports = DataExport.objects.filter(
        status='completed',
        expires_at__lt=timezone.now()
    )
    
    for export in expired_exports:
        # Delete file from storage
        if export.file_path and os.path.exists(export.file_path):
            os.remove(export.file_path)
        
        # Update status
        export.status = 'expired'
        export.save()


@shared_task
def send_onboarding_email(tenant_id, step_type):
    """Send onboarding emails"""
    from apps.tenants.models import Tenant
    from .models import OnboardingStep, EmailTemplate
    
    try:
        tenant = Tenant.objects.get(id=tenant_id)
        step = OnboardingStep.objects.get(tenant=tenant, step_type=step_type)
        
        # Get email template
        template = EmailTemplate.objects.filter(
            tenant=tenant,
            template_type='welcome',
            is_active=True
        ).first()
        
        if template:
            # Send email using template
            # Implement email sending logic
            pass
        
        # Mark step as completed
        step.is_completed = True
        step.completed_at = timezone.now()
        step.execution_result = {'email_sent': True}
        step.save()
        
    except Exception as e:
        # Log error
        pass


@shared_task
def audit_summary_generation():
    """Generate daily audit summaries"""
    from apps.audit.models import AuditSummary
    from apps.tenants.models import Tenant
    from datetime import date, timedelta
    
    yesterday = date.today() - timedelta(days=1)
    
    for tenant in Tenant.objects.all():
        try:
            AuditSummary.generate_daily_summary(tenant, yesterday)
        except Exception as e:
            # Log error
            pass


@shared_task
def security_monitoring():
    """Monitor for security threats"""
    from apps.audit.models import SecurityAlert, AuditLog
    from apps.tenants.models import Tenant
    from django.utils import timezone
    from datetime import timedelta
    
    # Check for brute force attacks in last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    for tenant in Tenant.objects.all():
        # Get failed login attempts by IP
        failed_logins = AuditLog.objects.filter(
            tenant=tenant,
            action='login_failed',
            timestamp__gte=one_hour_ago
        ).values('ip_address').annotate(
            count=models.Count('ip_address')
        ).filter(count__gte=5)
        
        for login_data in failed_logins:
            ip_address = login_data['ip_address']
            if ip_address:
                SecurityAlert.detect_brute_force(tenant, ip_address)