# apps/webhooks/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import hmac
import hashlib
import secrets

User = get_user_model()

class Webhook(models.Model):
    """Webhook configuration for event notifications"""
    
    # Supported webhook events
    EVENT_CHOICES = [
        ('user.registered', 'User Registered'),
        ('user.activated', 'User Activated'),
        ('user.login', 'User Login'),
        ('user.logout', 'User Logout'),
        ('user.profile_updated', 'User Profile Updated'),
        ('user.password_changed', 'User Password Changed'),
        ('mfa.enabled', 'MFA Enabled'),
        ('mfa.disabled', 'MFA Disabled'),
        ('api_key.created', 'API Key Created'),
        ('api_key.revoked', 'API Key Revoked'),
        ('role.assigned', 'Role Assigned'),
        ('role.revoked', 'Role Revoked'),
        ('tenant.created', 'Tenant Created'),
        ('audit.high_risk', 'High Risk Event'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='webhooks')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_webhooks')
    
    # Configuration
    name = models.CharField(max_length=100, help_text="Human-readable webhook name")
    url = models.URLField(max_length=2000, help_text="Webhook endpoint URL")
    events = models.JSONField(default=list, help_text="List of events to subscribe to")
    secret = models.CharField(max_length=64, help_text="Secret key for HMAC signature")
    
    # Settings
    is_active = models.BooleanField(default=True)
    timeout_seconds = models.PositiveIntegerField(default=30, help_text="Request timeout")
    max_retries = models.PositiveIntegerField(default=3, help_text="Max retry attempts")
    retry_delay_seconds = models.PositiveIntegerField(default=60, help_text="Initial retry delay")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    
    # Stats
    total_deliveries = models.PositiveIntegerField(default=0)
    successful_deliveries = models.PositiveIntegerField(default=0)
    failed_deliveries = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['tenant', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.tenant.slug}) → {self.url}"
    
    def save(self, *args, **kwargs):
        """Auto-generate secret if not provided"""
        if not self.secret:
            self.secret = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)
    
    def generate_signature(self, payload):
        """Generate HMAC signature for webhook payload"""
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        return hmac.new(
            self.secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
    
    def is_event_subscribed(self, event_type):
        """Check if webhook is subscribed to an event type"""
        return event_type in self.events
    
    def record_delivery(self, success=True):
        """Record webhook delivery attempt"""
        self.total_deliveries += 1
        self.last_triggered_at = timezone.now()
        
        if success:
            self.successful_deliveries += 1
            self.last_success_at = timezone.now()
        else:
            self.failed_deliveries += 1
        
        self.save(update_fields=[
            'total_deliveries', 'successful_deliveries', 'failed_deliveries',
            'last_triggered_at', 'last_success_at'
        ])

class WebhookDelivery(models.Model):
    """Record of webhook delivery attempts"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('retrying', 'Retrying'),
        ('abandoned', 'Abandoned'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    webhook = models.ForeignKey(Webhook, on_delete=models.CASCADE, related_name='deliveries')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    
    # Event details
    event_type = models.CharField(max_length=50, help_text="Type of event triggered")
    event_id = models.UUIDField(help_text="Unique event identifier")
    payload = models.JSONField(help_text="Event payload sent to webhook")
    
    # Delivery details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    response_status = models.PositiveIntegerField(null=True, blank=True, help_text="HTTP response status")
    response_body = models.TextField(blank=True, help_text="Response body (truncated)")
    response_headers = models.JSONField(default=dict, help_text="Response headers")
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    scheduled_at = models.DateTimeField(default=timezone.now, db_index=True, help_text="When to attempt delivery")
    attempted_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Retry logic
    attempt_count = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True, db_index=True)
    
    # Error tracking
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'scheduled_at']),
            models.Index(fields=['webhook', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.event_type} → {self.webhook.name} ({self.status})"
    
    def can_retry(self):
        """Check if this delivery can be retried"""
        return (
            self.status in ['failed', 'retrying'] and
            self.attempt_count < self.max_attempts
        )
    
    def calculate_next_retry(self):
        """Calculate next retry time using exponential backoff"""
        if not self.can_retry():
            return None
        
        # Exponential backoff: base_delay * 2^attempt_count
        delay_seconds = self.webhook.retry_delay_seconds * (2 ** self.attempt_count)
        # Cap at 1 hour
        delay_seconds = min(delay_seconds, 3600)
        
        return timezone.now() + timezone.timedelta(seconds=delay_seconds)

class WebhookEvent:
    """Helper class for webhook event management"""
    
    @classmethod
    def trigger(cls, tenant, event_type, data, event_id=None, actor=None):
        """
        Trigger webhook deliveries for an event
        
        Args:
            tenant: Tenant instance
            event_type: Event type string (e.g., 'user.registered')
            data: Event payload data
            event_id: Optional unique event ID
            actor: Optional user who triggered the event
        """
        from .tasks import deliver_webhook  # Import here to avoid circular imports
        
        if not event_id:
            event_id = uuid.uuid4()
        
        # Find all active webhooks subscribed to this event
        webhooks = Webhook.objects.filter(
            tenant=tenant,
            is_active=True
        ).filter(events__contains=[event_type])
        
        for webhook in webhooks:
            # Create delivery record
            delivery = WebhookDelivery.objects.create(
                webhook=webhook,
                tenant=tenant,
                event_type=event_type,
                event_id=event_id,
                payload=data,
                max_attempts=webhook.max_retries
            )
            
            # Queue delivery task
            deliver_webhook.delay(delivery.id)
    
    @classmethod
    def get_supported_events(cls):
        """Get list of supported event types"""
        return [choice[0] for choice in Webhook.EVENT_CHOICES]