# audit/models.py

import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

User = get_user_model()

class AuditLog(models.Model):
    """
    Model for storing audit logs of system events.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Event type and category
    EVENT_CATEGORIES = (
        ('auth', _('Authentication')),
        ('authorization', _('Authorization')),
        ('user', _('User Management')),
        ('role', _('Role Management')),
        ('permission', _('Permission Management')),
        ('api_key', _('API Key Management')),
        ('oauth2', _('OAuth2')),
        ('admin', _('Administrative')),
        ('system', _('System')),
    )
    category = models.CharField(_('category'), max_length=20, choices=EVENT_CATEGORIES)
    
    EVENT_TYPES = (
        # Authentication events
        ('login_success', _('Login Success')),
        ('login_failure', _('Login Failure')),
        ('logout', _('Logout')),
        ('password_reset_request', _('Password Reset Request')),
        ('password_reset_complete', _('Password Reset Complete')),
        ('password_change', _('Password Change')),
        ('account_locked', _('Account Locked')),
        ('account_unlocked', _('Account Unlocked')),
        ('2fa_enabled', _('2FA Enabled')),
        ('2fa_disabled', _('2FA Disabled')),
        ('2fa_success', _('2FA Success')),
        ('2fa_failure', _('2FA Failure')),
        
        # Authorization events
        ('access_denied', _('Access Denied')),
        ('access_granted', _('Access Granted')),
        ('role_assigned', _('Role Assigned')),
        ('role_removed', _('Role Removed')),
        ('permission_assigned', _('Permission Assigned')),
        ('permission_removed', _('Permission Removed')),
        
        # User management events
        ('user_created', _('User Created')),
        ('user_updated', _('User Updated')),
        ('user_deleted', _('User Deleted')),
        ('user_activated', _('User Activated')),
        ('user_deactivated', _('User Deactivated')),
        
        # Role and permission management events
        ('role_created', _('Role Created')),
        ('role_updated', _('Role Updated')),
        ('role_deleted', _('Role Deleted')),
        ('permission_created', _('Permission Created')),
        ('permission_updated', _('Permission Updated')),
        ('permission_deleted', _('Permission Deleted')),
        
        # API key events
        ('api_key_created', _('API Key Created')),
        ('api_key_updated', _('API Key Updated')),
        ('api_key_deleted', _('API Key Deleted')),
        ('api_key_used', _('API Key Used')),
        
        # OAuth2 events
        ('oauth2_client_created', _('OAuth2 Client Created')),
        ('oauth2_client_updated', _('OAuth2 Client Updated')),
        ('oauth2_client_deleted', _('OAuth2 Client Deleted')),
        ('oauth2_authorization_granted', _('OAuth2 Authorization Granted')),
        ('oauth2_token_issued', _('OAuth2 Token Issued')),
        ('oauth2_token_refreshed', _('OAuth2 Token Refreshed')),
        ('oauth2_token_revoked', _('OAuth2 Token Revoked')),
        
        # Administrative events
        ('settings_changed', _('Settings Changed')),
        ('backup_created', _('Backup Created')),
        ('backup_restored', _('Backup Restored')),
        
        # System events
        ('system_error', _('System Error')),
        ('system_warning', _('System Warning')),
        ('system_info', _('System Information')),
    )
    event_type = models.CharField(_('event type'), max_length=50, choices=EVENT_TYPES)
    
    # Related user (actor)
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL,
        null=True, 
        blank=True, 
        related_name='audit_logs',
        verbose_name=_('user')
    )
    
    # Target object (optional)
    content_type = models.ForeignKey(
        ContentType, 
        on_delete=models.SET_NULL,
        null=True, 
        blank=True,
        verbose_name=_('content type')
    )
    object_id = models.CharField(_('object ID'), max_length=50, blank=True, null=True)
    target = GenericForeignKey('content_type', 'object_id')
    
    # Event details
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    ip_address = models.GenericIPAddressField(_('IP address'), blank=True, null=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    details = models.JSONField(_('details'), default=dict, blank=True)
    success = models.BooleanField(_('success'), default=True)
    
    # For maintaining data integrity
    hash = models.CharField(_('hash'), max_length=128, blank=True, editable=False)
    previous_hash = models.CharField(_('previous hash'), max_length=128, blank=True, editable=False)
    
    class Meta:
        verbose_name = _('audit log')
        verbose_name_plural = _('audit logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['event_type']),
            models.Index(fields=['category']),
            models.Index(fields=['content_type', 'object_id']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.timestamp}"
    
    def save(self, *args, **kwargs):
        # Compute hash before saving
        if not self.hash:
            self.compute_hash()
        super().save(*args, **kwargs)
    
    def compute_hash(self):
        """
        Compute a hash of this log entry, incorporating the previous hash to create a chain.
        """
        import hashlib
        import json
        
        # Get the previous log entry to chain hashes
        previous_log = AuditLog.objects.order_by('-timestamp').first()
        if previous_log:
            self.previous_hash = previous_log.hash
        
        # Create a string to hash based on the current log entry
        data_to_hash = {
            'timestamp': str(self.timestamp) if self.timestamp else str(self.id),
            'event_type': self.event_type,
            'user_id': str(self.user.id) if self.user else '',
            'details': json.dumps(self.details, sort_keys=True),
            'previous_hash': self.previous_hash,
        }
        
        # Convert the data to a string and create a hash
        data_string = json.dumps(data_to_hash, sort_keys=True)
        self.hash = hashlib.sha256(data_string.encode()).hexdigest()