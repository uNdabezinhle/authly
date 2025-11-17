# apps/audit/models.py
from django.db import models
from django.contrib.auth import get_user_model
import uuid

User = get_user_model()

class AuditLog(models.Model):
    """Comprehensive audit logging for security and compliance"""
    
    # Audit action types
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('login_failed', 'Login Failed'),
        ('register', 'User Registration'),
        ('activate', 'Account Activation'),
        ('password_change', 'Password Changed'),
        ('password_reset', 'Password Reset'),
        ('mfa_enable', 'MFA Enabled'),
        ('mfa_disable', 'MFA Disabled'),
        ('mfa_verify', 'MFA Verification'),
        ('profile_update', 'Profile Updated'),
        ('avatar_upload', 'Avatar Uploaded'),
        ('api_key_create', 'API Key Created'),
        ('api_key_revoke', 'API Key Revoked'),
        ('role_assign', 'Role Assigned'),
        ('role_revoke', 'Role Revoked'),
        ('permission_check', 'Permission Checked'),
        ('webhook_create', 'Webhook Created'),
        ('webhook_update', 'Webhook Updated'),
        ('webhook_delete', 'Webhook Deleted'),
        ('tenant_create', 'Tenant Created'),
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
    ]
    
    # Risk levels
    RISK_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='audit_logs')
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='audit_logs')
    actor_email = models.EmailField(blank=True, help_text="Email preserved even if user is deleted")
    
    # Action details
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    resource = models.CharField(max_length=100, help_text="Resource type (user, api_key, role, etc.)")
    resource_id = models.UUIDField(null=True, blank=True, help_text="ID of affected resource")
    resource_name = models.CharField(max_length=255, blank=True, help_text="Human readable resource name")
    
    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_id = models.CharField(max_length=255, blank=True, db_index=True)
    request_id = models.CharField(max_length=255, blank=True, help_text="Unique request identifier")
    
    # Audit metadata
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default='low', db_index=True)
    success = models.BooleanField(default=True, help_text="Whether the action succeeded")
    error_message = models.TextField(blank=True, help_text="Error details if action failed")
    metadata = models.JSONField(default=dict, help_text="Additional context data")
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', '-timestamp']),
            models.Index(fields=['actor', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['risk_level', '-timestamp']),
            models.Index(fields=['success', '-timestamp']),
        ]
    
    def __str__(self):
        actor_str = self.actor_email or self.actor or 'System'
        return f"{actor_str} - {self.get_action_display()} - {self.timestamp}"
    
    @classmethod
    def create_log(cls, action, user=None, details=None, risk_level='low', tenant=None):
        """
        Simplified convenience method for creating audit logs
        """
        return cls.objects.create(
            tenant=tenant,
            actor=user,
            actor_email=user.email if user else '',
            action=action,
            risk_level=risk_level,
            metadata=details or {}
        )
    
    @classmethod
    def log_action(cls, tenant, action, request=None, actor=None, resource=None, 
                   resource_id=None, resource_name=None, success=True, 
                   error_message='', risk_level='low', metadata=None):
        """
        Convenience method to create audit log entries
        
        Args:
            tenant: Tenant instance
            action: Action type (from ACTION_CHOICES)
            request: Django request object (optional)
            actor: User performing the action (optional)
            resource: Resource type being acted upon
            resource_id: ID of the resource
            resource_name: Human-readable name of the resource
            success: Whether the action succeeded
            error_message: Error details if action failed
            risk_level: Risk level of the action
            metadata: Additional context data
        """
        # Extract request context
        ip_address = None
        user_agent = ''
        session_id = ''
        request_id = ''
        
        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:1000]  # Limit length
            session_id = request.session.session_key or ''
            request_id = getattr(request, 'id', '')
            
            # Try to get actor from request if not provided
            if not actor and hasattr(request, 'user') and request.user.is_authenticated:
                actor = request.user
        
        # Store actor email for preservation
        actor_email = actor.email if actor else ''
        
        return cls.objects.create(
            tenant=tenant,
            actor=actor,
            actor_email=actor_email,
            action=action,
            resource=resource or '',
            resource_id=resource_id,
            resource_name=resource_name or '',
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            risk_level=risk_level,
            success=success,
            error_message=error_message,
            metadata=metadata or {}
        )
    
    @staticmethod
    def _get_client_ip(request):
        """Get the client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class AuditSummary(models.Model):
    """Aggregated audit statistics for analytics"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='audit_summaries')
    
    # Time period
    date = models.DateField(db_index=True)
    hour = models.IntegerField(null=True, blank=True, help_text="Hour of day (0-23) for hourly summaries")
    
    # Counts by action type
    login_count = models.IntegerField(default=0)
    logout_count = models.IntegerField(default=0)
    failed_login_count = models.IntegerField(default=0)
    registration_count = models.IntegerField(default=0)
    api_call_count = models.IntegerField(default=0)
    role_change_count = models.IntegerField(default=0)
    
    # Risk level counts
    low_risk_count = models.IntegerField(default=0)
    medium_risk_count = models.IntegerField(default=0)
    high_risk_count = models.IntegerField(default=0)
    critical_risk_count = models.IntegerField(default=0)
    
    # Success/failure stats
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    
    # Top actors and IPs (JSON fields for analytics)
    top_actors = models.JSONField(default=list, help_text="Most active users: [{'email': 'user@example.com', 'count': 50}]")
    top_ips = models.JSONField(default=list, help_text="Most active IP addresses: [{'ip': '192.168.1.1', 'count': 30}]")
    top_actions = models.JSONField(default=list, help_text="Most frequent actions: [{'action': 'login', 'count': 100}]")
    
    # Anomaly detection flags
    unusual_activity = models.BooleanField(default=False, help_text="Flagged for unusual activity patterns")
    anomaly_details = models.JSONField(default=dict, help_text="Details about detected anomalies")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = [['tenant', 'date', 'hour']]
        ordering = ['-date', '-hour']
        verbose_name = 'Audit Summary'
        verbose_name_plural = 'Audit Summaries'
        indexes = [
            models.Index(fields=['tenant', '-date']),
            models.Index(fields=['date', 'hour']),
            models.Index(fields=['unusual_activity']),
        ]
    
    def __str__(self):
        period = f"{self.date}"
        if self.hour is not None:
            period += f" {self.hour:02d}:00"
        return f"Audit Summary for {self.tenant} - {period}"
    
    @classmethod
    def generate_daily_summary(cls, tenant, date):
        """Generate daily audit summary for a tenant"""
        from django.db.models import Count, Q
        from datetime import datetime
        
        # Get logs for the day
        start_time = datetime.combine(date, datetime.min.time())
        end_time = datetime.combine(date, datetime.max.time())
        
        logs = AuditLog.objects.filter(
            tenant=tenant,
            timestamp__range=[start_time, end_time]
        )
        
        # Count by action types
        action_counts = logs.values('action').annotate(count=Count('action'))
        action_map = {item['action']: item['count'] for item in action_counts}
        
        # Count by risk levels
        risk_counts = logs.values('risk_level').annotate(count=Count('risk_level'))
        risk_map = {item['risk_level']: item['count'] for item in risk_counts}
        
        # Top actors
        top_actors = list(logs.values('actor_email').exclude(
            actor_email=''
        ).annotate(count=Count('actor_email')).order_by('-count')[:10])
        
        # Top IPs
        top_ips = list(logs.values('ip_address').exclude(
            ip_address__isnull=True
        ).annotate(count=Count('ip_address')).order_by('-count')[:10])
        
        # Top actions
        top_actions = list(logs.values('action').annotate(
            count=Count('action')
        ).order_by('-count')[:10])
        
        # Success/failure counts
        success_count = logs.filter(success=True).count()
        failure_count = logs.filter(success=False).count()
        
        # Create or update summary
        summary, created = cls.objects.update_or_create(
            tenant=tenant,
            date=date,
            hour=None,  # Daily summary
            defaults={
                'login_count': action_map.get('login', 0),
                'logout_count': action_map.get('logout', 0),
                'failed_login_count': action_map.get('login_failed', 0),
                'registration_count': action_map.get('register', 0),
                'api_call_count': action_map.get('api_call', 0),
                'role_change_count': action_map.get('role_assign', 0) + action_map.get('role_revoke', 0),
                'low_risk_count': risk_map.get('low', 0),
                'medium_risk_count': risk_map.get('medium', 0),
                'high_risk_count': risk_map.get('high', 0),
                'critical_risk_count': risk_map.get('critical', 0),
                'success_count': success_count,
                'failure_count': failure_count,
                'top_actors': top_actors,
                'top_ips': top_ips,
                'top_actions': top_actions,
            }
        )
        
        # Basic anomaly detection
        cls._detect_anomalies(summary)
        
        return summary
    
    @classmethod
    def _detect_anomalies(cls, summary):
        """Basic anomaly detection for audit summaries"""
        anomalies = {}
        
        # High failure rate
        total_actions = summary.success_count + summary.failure_count
        if total_actions > 0:
            failure_rate = summary.failure_count / total_actions
            if failure_rate > 0.1:  # More than 10% failure rate
                anomalies['high_failure_rate'] = failure_rate
        
        # Too many failed logins
        if summary.failed_login_count > 50:
            anomalies['excessive_failed_logins'] = summary.failed_login_count
        
        # High critical/high risk events
        critical_high_count = summary.critical_risk_count + summary.high_risk_count
        if critical_high_count > 10:
            anomalies['high_risk_events'] = critical_high_count
        
        # Update anomaly flags
        summary.unusual_activity = bool(anomalies)
        summary.anomaly_details = anomalies
        summary.save(update_fields=['unusual_activity', 'anomaly_details'])


class SecurityAlert(models.Model):
    """Security alerts based on audit log analysis"""
    
    ALERT_TYPES = [
        ('brute_force', 'Brute Force Attack'),
        ('multiple_failures', 'Multiple Login Failures'),
        ('unusual_location', 'Unusual Login Location'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('data_exfiltration', 'Potential Data Exfiltration'),
        ('account_takeover', 'Account Takeover'),
        ('suspicious_api_usage', 'Suspicious API Usage'),
        ('failed_mfa', 'Multiple MFA Failures'),
    ]
    
    SEVERITY_LEVELS = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='security_alerts')
    
    # Alert details
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='warning', db_index=True)
    title = models.CharField(max_length=200)
    description = models.TextField()
    
    # Context
    affected_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='security_alerts')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    related_logs = models.ManyToManyField(AuditLog, related_name='security_alerts')
    
    # Alert metadata
    detection_data = models.JSONField(default=dict, help_text="Data used for detection")
    recommendations = models.JSONField(default=list, help_text="Recommended actions")
    
    # Alert lifecycle
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')
    resolution_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Security Alert'
        verbose_name_plural = 'Security Alerts'
        indexes = [
            models.Index(fields=['tenant', '-created_at']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
            models.Index(fields=['alert_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.get_severity_display()} - {self.title} ({self.tenant})"
    
    def resolve(self, resolved_by=None, notes=""):
        """Mark alert as resolved"""
        from django.utils import timezone
        
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.resolved_by = resolved_by
        self.resolution_notes = notes
        self.save()
    
    @classmethod
    def detect_brute_force(cls, tenant, ip_address, time_window_minutes=15, threshold=5):
        """Detect brute force attacks based on failed login attempts"""
        from django.utils import timezone
        from datetime import timedelta
        
        cutoff_time = timezone.now() - timedelta(minutes=time_window_minutes)
        
        failed_attempts = AuditLog.objects.filter(
            tenant=tenant,
            action='login_failed',
            ip_address=ip_address,
            timestamp__gte=cutoff_time
        ).count()
        
        if failed_attempts >= threshold:
            # Check if alert already exists
            existing_alert = cls.objects.filter(
                tenant=tenant,
                alert_type='brute_force',
                source_ip=ip_address,
                status='open',
                created_at__gte=cutoff_time
            ).first()
            
            if not existing_alert:
                alert = cls.objects.create(
                    tenant=tenant,
                    alert_type='brute_force',
                    severity='critical',
                    title=f"Brute force attack from {ip_address}",
                    description=f"Detected {failed_attempts} failed login attempts from IP {ip_address} in {time_window_minutes} minutes",
                    source_ip=ip_address,
                    detection_data={
                        'failed_attempts': failed_attempts,
                        'time_window': time_window_minutes,
                        'threshold': threshold
                    },
                    recommendations=[
                        'Block IP address',
                        'Review authentication logs',
                        'Consider implementing account lockout',
                        'Enable MFA for affected accounts'
                    ]
                )
                
                # Link related audit logs
                related_logs = AuditLog.objects.filter(
                    tenant=tenant,
                    action='login_failed',
                    ip_address=ip_address,
                    timestamp__gte=cutoff_time
                )
                alert.related_logs.set(related_logs)
                
                return alert
        
        return None