# api_keys/models.py

import uuid
import secrets
import string
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

User = get_user_model()

def generate_key():
    """Generate a random API key."""
    # Generate a secure random string of length 32
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(48))

class APIKey(models.Model):
    """
    Model for API keys used for authentication.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255)
    prefix = models.CharField(_('prefix'), max_length=8, unique=True, editable=False)
    key = models.CharField(_('key'), max_length=550, editable=False)
    
    # Relations
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='api_keys',
        verbose_name=_('user')
    )
    
    # Permissions - can reference specific roles/permissions or use a scopes field
    scopes = models.JSONField(_('scopes'), default=list, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True)
    last_used_at = models.DateTimeField(_('last used at'), null=True, blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    description = models.TextField(_('description'), blank=True)
    
    # Restrictions
    allowed_ips = models.JSONField(_('allowed IPs'), default=list, blank=True)
    allowed_referers = models.JSONField(_('allowed referers'), default=list, blank=True)
    rate_limit_requests = models.PositiveIntegerField(_('rate limit requests'), default=0)
    rate_limit_period = models.PositiveIntegerField(_('rate limit period in seconds'), default=0)
    
    class Meta:
        verbose_name = _('API key')
        verbose_name_plural = _('API keys')
        ordering = ['-created_at']
        unique_together = ('user', 'name')
    
    def __str__(self):
        return f"{self.name} ({self.prefix}...)"
    
    def save(self, *args, **kwargs):
        # Generate key and prefix on first save
        if not self.key:
            self.key = generate_key()
            self.prefix = self.key[:8]
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """
        Check if the API key is valid (not expired and active).
        """
        if not self.is_active:
            return False
        
        if self.expires_at and self.expires_at < timezone.now():
            return False
            
        return True
    
    def update_last_used(self):
        """
        Update the last used timestamp.
        """
        self.last_used_at = timezone.now()
        self.save(update_fields=['last_used_at'])
    
    def is_allowed_ip(self, ip_address):
        """
        Check if the provided IP address is allowed to use this API key.
        """
        if not self.allowed_ips:
            return True  # No IP restrictions
        
        return ip_address in self.allowed_ips
    
    def is_allowed_referer(self, referer):
        """
        Check if the provided referer is allowed to use this API key.
        """
        if not self.allowed_referers:
            return True  # No referer restrictions
        
        # Check if any of the allowed referers is a prefix of the provided referer
        return any(referer.startswith(allowed) for allowed in self.allowed_referers)
    
    def check_rate_limit(self):
        """
        Check if the API key has exceeded its rate limit.
        """
        if not self.rate_limit_requests or not self.rate_limit_period:
            return True  # No rate limit
        
        # Get recent requests
        recent_requests = APIKeyUsage.objects.filter(
            api_key=self,
            timestamp__gte=timezone.now() - timezone.timedelta(seconds=self.rate_limit_period)
        ).count()
        
        return recent_requests < self.rate_limit_requests


class APIKeyUsage(models.Model):
    """
    Model for tracking API key usage.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    api_key = models.ForeignKey(
        APIKey, 
        on_delete=models.CASCADE, 
        related_name='usage_logs',
        verbose_name=_('API key')
    )
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    endpoint = models.CharField(_('endpoint'), max_length=255)
    method = models.CharField(_('HTTP method'), max_length=10)
    ip_address = models.GenericIPAddressField(_('IP address'), null=True, blank=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    response_status = models.PositiveSmallIntegerField(_('response status'), null=True, blank=True)
    response_time_ms = models.PositiveIntegerField(_('response time (ms)'), null=True, blank=True)
    
    class Meta:
        verbose_name = _('API key usage')
        verbose_name_plural = _('API key usages')
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.api_key} - {self.endpoint} - {self.timestamp}"