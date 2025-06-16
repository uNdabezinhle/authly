# sso/models.py

import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from tenants.models import Tenant

User = get_user_model()

class IdentityProvider(models.Model):
    """
    Model for external identity providers (IdPs) for SSO authentication.
    """
    PROTOCOL_CHOICES = (
        ('saml', _('SAML 2.0')),
        ('oidc', _('OpenID Connect')),
        ('oauth2', _('OAuth 2.0')),
        ('ldap', _('LDAP/Active Directory')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='identity_providers',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    name = models.CharField(_('name'), max_length=255)
    description = models.TextField(_('description'), blank=True)
    protocol = models.CharField(_('protocol'), max_length=10, choices=PROTOCOL_CHOICES)
    is_active = models.BooleanField(_('active'), default=True)
    
    # Configuration fields (varies by protocol)
    config = models.JSONField(_('configuration'), default=dict)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('identity provider')
        verbose_name_plural = _('identity providers')
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.get_protocol_display()})"
    
    @property
    def protocol_handler(self):
        """
        Returns the appropriate protocol handler for this IdP.
        """
        if self.protocol == 'saml':
            from .handlers import SAMLHandler
            return SAMLHandler(self)
        elif self.protocol == 'oidc':
            from .handlers import OIDCHandler
            return OIDCHandler(self)
        elif self.protocol == 'oauth2':
            from .handlers import OAuth2Handler
            return OAuth2Handler(self)
        elif self.protocol == 'ldap':
            from .handlers import LDAPHandler
            return LDAPHandler(self)
        return None


class SSOUserMapping(models.Model):
    """
    Model for mapping external user identities to local users.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='sso_user_mappings',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sso_mappings')
    identity_provider = models.ForeignKey(
        IdentityProvider, 
        on_delete=models.CASCADE, 
        related_name='user_mappings',
        null=True, 
        blank=True, 
    )
    
    # External identifiers
    external_id = models.CharField(_('external ID'), max_length=255)
    external_email = models.EmailField(_('external email'), blank=True)
    external_username = models.CharField(_('external username'), max_length=255, blank=True)
    
    # Additional profile data from IdP
    profile_data = models.JSONField(_('profile data'), default=dict, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    last_login = models.DateTimeField(_('last login'), null=True, blank=True)
    
    class Meta:
        verbose_name = _('SSO user mapping')
        verbose_name_plural = _('SSO user mappings')
        unique_together = [('identity_provider', 'external_id')]
        indexes = [
            models.Index(fields=['identity_provider', 'external_id']),
            models.Index(fields=['identity_provider', 'external_email']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.identity_provider.name} - {self.external_id}"


class SSOSession(models.Model):
    """
    Model for tracking SSO authentication sessions.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='sso_sessions',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE)
    
    # Session data
    session_id = models.CharField(_('session ID'), max_length=255, unique=True)
    started_at = models.DateTimeField(_('started at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'))
    ip_address = models.GenericIPAddressField(_('IP address'), blank=True, null=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    
    # State information
    is_active = models.BooleanField(_('active'), default=True)
    logged_out_at = models.DateTimeField(_('logged out at'), blank=True, null=True)
    
    class Meta:
        verbose_name = _('SSO session')
        verbose_name_plural = _('SSO sessions')
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Session {self.session_id} for {self.user_mapping.user.email}"
    
    def is_valid(self):
        """
        Check if the session is valid (not expired and active).
        """
        from django.utils import timezone
        return self.is_active and self.expires_at > timezone.now()
    
    def logout(self):
        """
        Mark the session as logged out.
        """
        from django.utils import timezone
        self.is_active = False
        self.logged_out_at = timezone.now()
        self.save(update_fields=['is_active', 'logged_out_at'])