import uuid
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class TenantBranding(models.Model):
    """Tenant-specific branding and customization"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField('tenants.Tenant', on_delete=models.CASCADE, related_name='branding')
    
    # Visual branding
    logo_url = models.URLField(blank=True, help_text="URL to company logo")
    primary_color = models.CharField(max_length=7, default='#007bff', help_text="Primary brand color (hex)")
    secondary_color = models.CharField(max_length=7, default='#6c757d', help_text="Secondary brand color (hex)")
    background_color = models.CharField(max_length=7, default='#ffffff', help_text="Background color (hex)")
    font_family = models.CharField(max_length=100, default='Inter', help_text="Primary font family")
    
    # Login page customization
    login_background_image = models.URLField(blank=True, help_text="Login page background image")
    login_title = models.CharField(max_length=100, default='Sign In', help_text="Login page title")
    login_subtitle = models.CharField(max_length=200, blank=True, help_text="Login page subtitle")
    login_footer_text = models.TextField(blank=True, help_text="Footer text on login page")
    
    # Contact information
    company_name = models.CharField(max_length=200, blank=True)
    support_email = models.EmailField(blank=True)
    support_phone = models.CharField(max_length=50, blank=True)
    website_url = models.URLField(blank=True)
    
    # Terms and policies
    terms_of_service_url = models.URLField(blank=True)
    privacy_policy_url = models.URLField(blank=True)
    acceptable_use_policy_url = models.URLField(blank=True)
    
    # Email customization
    email_from_name = models.CharField(max_length=100, blank=True, help_text="Name shown in outgoing emails")
    email_from_address = models.EmailField(blank=True, help_text="Email address for outgoing emails")
    email_header_logo = models.URLField(blank=True, help_text="Logo for email headers")
    email_footer_text = models.TextField(blank=True, help_text="Footer text for emails")
    
    # Advanced settings
    custom_css = models.TextField(blank=True, help_text="Custom CSS for additional styling")
    custom_javascript = models.TextField(blank=True, help_text="Custom JavaScript for advanced features")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = 'Tenant Branding'
        verbose_name_plural = 'Tenant Branding'
    
    def __str__(self):
        return f"Branding for {self.tenant.name}"


class EmailTemplate(models.Model):
    """Customizable email templates per tenant"""
    
    TEMPLATE_TYPES = [
        ('welcome', 'Welcome Email'),
        ('verification', 'Email Verification'),
        ('password_reset', 'Password Reset'),
        ('invitation', 'User Invitation'),
        ('mfa_setup', 'MFA Setup'),
        ('security_alert', 'Security Alert'),
        ('billing_reminder', 'Billing Reminder'),
        ('subscription_change', 'Subscription Change'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='email_templates')
    
    template_type = models.CharField(max_length=30, choices=TEMPLATE_TYPES)
    name = models.CharField(max_length=100, help_text="Template name")
    subject = models.CharField(max_length=200, help_text="Email subject line")
    
    # Template content
    html_content = models.TextField(help_text="HTML version of email")
    text_content = models.TextField(help_text="Plain text version of email")
    
    # Template variables documentation
    available_variables = models.JSONField(
        default=list,
        help_text="Available template variables: ['user_name', 'reset_link', 'company_name']"
    )
    
    # Status
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False, help_text="Use as default for this template type")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        unique_together = [['tenant', 'template_type', 'is_default']]
        verbose_name = 'Email Template'
        verbose_name_plural = 'Email Templates'
    
    def __str__(self):
        return f"{self.tenant.name} - {self.get_template_type_display()}"


class TenantUsageMetrics(models.Model):
    """Track tenant usage for monitoring and billing"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='usage_metrics')
    
    # Time period
    date = models.DateField()
    hour = models.IntegerField(null=True, blank=True, help_text="Hour of day (0-23) for hourly metrics")
    
    # API usage
    api_calls_total = models.IntegerField(default=0)
    api_calls_auth = models.IntegerField(default=0)
    api_calls_users = models.IntegerField(default=0)
    api_calls_roles = models.IntegerField(default=0)
    api_calls_audit = models.IntegerField(default=0)
    
    # User activity
    active_users = models.IntegerField(default=0)
    new_users = models.IntegerField(default=0)
    login_count = models.IntegerField(default=0)
    
    # Storage usage (in bytes)
    storage_used = models.BigIntegerField(default=0)
    audit_logs_size = models.BigIntegerField(default=0)
    user_uploads_size = models.BigIntegerField(default=0)
    
    # Feature usage
    mfa_enabled_users = models.IntegerField(default=0)
    api_keys_active = models.IntegerField(default=0)
    webhooks_triggered = models.IntegerField(default=0)
    sso_logins = models.IntegerField(default=0)
    
    # Billing metrics
    billable_api_calls = models.IntegerField(default=0)
    overage_charges = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['tenant', 'date', 'hour']]
        ordering = ['-date', '-hour']
        indexes = [
            models.Index(fields=['tenant', '-date']),
            models.Index(fields=['date', 'hour']),
        ]
    
    def __str__(self):
        period = str(self.date)
        if self.hour is not None:
            period += f" {self.hour:02d}:00"
        return f"Usage for {self.tenant.name} - {period}"


class DataExport(models.Model):
    """Track data exports for backup and compliance"""
    
    EXPORT_TYPES = [
        ('backup', 'Full Backup'),
        ('users', 'Users Export'),
        ('audit_logs', 'Audit Logs Export'),
        ('compliance', 'Compliance Export'),
        ('gdpr', 'GDPR Data Export'),
    ]
    
    EXPORT_FORMATS = [
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xml', 'XML'),
        ('encrypted', 'Encrypted Archive'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='data_exports')
    
    export_type = models.CharField(max_length=20, choices=EXPORT_TYPES)
    export_format = models.CharField(max_length=20, choices=EXPORT_FORMATS, default='json')
    
    # Request details
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='requested_exports')
    requested_at = models.DateTimeField(auto_now_add=True)
    
    # Filters and options
    date_from = models.DateTimeField(null=True, blank=True)
    date_to = models.DateTimeField(null=True, blank=True)
    filters = models.JSONField(default=dict, help_text="Additional filter criteria")
    include_deleted = models.BooleanField(default=False)
    
    # Export status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress_percentage = models.IntegerField(default=0)
    
    # Results
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True)
    encryption_key = models.CharField(max_length=100, blank=True, help_text="Encryption key for encrypted exports")
    download_url = models.URLField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Processing details
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    # Statistics
    records_exported = models.IntegerField(default=0)
    processing_time_seconds = models.IntegerField(null=True, blank=True)
    
    class Meta:
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['tenant', '-requested_at']),
            models.Index(fields=['status', '-requested_at']),
            models.Index(fields=['export_type']),
        ]
    
    def __str__(self):
        return f"{self.get_export_type_display()} for {self.tenant.name} - {self.status}"


class ComplianceSettings(models.Model):
    """GDPR and regulatory compliance settings per tenant"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField('tenants.Tenant', on_delete=models.CASCADE, related_name='compliance_settings')
    
    # GDPR settings
    gdpr_enabled = models.BooleanField(default=True)
    data_retention_days = models.IntegerField(default=2555, help_text="Data retention period (7 years default)")
    automatic_deletion = models.BooleanField(default=False, help_text="Automatically delete data after retention period")
    
    # Consent management
    require_explicit_consent = models.BooleanField(default=True)
    consent_tracking = models.BooleanField(default=True)
    cookie_consent_required = models.BooleanField(default=True)
    
    # Data processing
    data_processing_purposes = models.JSONField(
        default=list,
        help_text="Purposes for data processing: ['authentication', 'analytics', 'support']"
    )
    third_party_sharing = models.BooleanField(default=False)
    third_party_list = models.JSONField(default=list, help_text="List of third parties data is shared with")
    
    # Data subject rights
    right_to_access = models.BooleanField(default=True)
    right_to_rectification = models.BooleanField(default=True)
    right_to_erasure = models.BooleanField(default=True)
    right_to_portability = models.BooleanField(default=True)
    right_to_restrict = models.BooleanField(default=True)
    
    # Audit and monitoring
    audit_all_access = models.BooleanField(default=True)
    breach_notification_enabled = models.BooleanField(default=True)
    breach_notification_email = models.EmailField(blank=True)
    
    # Regional compliance
    data_residency_country = models.CharField(max_length=2, blank=True, help_text="ISO country code for data residency")
    compliance_frameworks = models.JSONField(
        default=list,
        help_text="Applicable compliance frameworks: ['GDPR', 'CCPA', 'SOC2', 'HIPAA']"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = 'Compliance Settings'
        verbose_name_plural = 'Compliance Settings'
    
    def __str__(self):
        return f"Compliance settings for {self.tenant.name}"


class OnboardingStep(models.Model):
    """Automated onboarding steps for new tenants"""
    
    STEP_TYPES = [
        ('welcome_email', 'Send Welcome Email'),
        ('create_admin', 'Create Admin User'),
        ('setup_roles', 'Setup Default Roles'),
        ('configure_branding', 'Configure Branding'),
        ('setup_sso', 'Setup SSO'),
        ('create_api_key', 'Create API Key'),
        ('webhook_setup', 'Setup Webhooks'),
        ('compliance_review', 'Compliance Review'),
        ('training_materials', 'Send Training Materials'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='onboarding_steps')
    
    step_type = models.CharField(max_length=30, choices=STEP_TYPES)
    order = models.IntegerField(default=0)
    
    # Step configuration
    title = models.CharField(max_length=200)
    description = models.TextField()
    instructions = models.TextField(blank=True)
    is_required = models.BooleanField(default=False)
    
    # Automation settings
    auto_execute = models.BooleanField(default=False)
    delay_hours = models.IntegerField(default=0, help_text="Delay before auto-execution")
    
    # Dependencies
    depends_on_steps = models.ManyToManyField('self', blank=True, symmetrical=False)
    
    # Status
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    completed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Results
    execution_result = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['order', 'created_at']
        unique_together = [['tenant', 'step_type']]
        indexes = [
            models.Index(fields=['tenant', 'order']),
            models.Index(fields=['is_completed']),
        ]
    
    def __str__(self):
        return f"{self.title} for {self.tenant.name}"