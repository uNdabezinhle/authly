# oauth2/models.py

import uuid
import secrets
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from tenants.models import Tenant  # Add this import

User = get_user_model()

class OAuth2Client(models.Model):
    """
    Model for OAuth2 client applications.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255)
    client_id = models.CharField(_('client ID'), max_length=100, unique=True, editable=False)
    client_secret = models.CharField(_('client secret'), max_length=255, editable=False)
    
    # Client type
    CLIENT_TYPE_CHOICES = (
        ('confidential', _('Confidential')),
        ('public', _('Public')),
    )
    client_type = models.CharField(_('client type'), max_length=15, choices=CLIENT_TYPE_CHOICES, default='confidential')
    
    # Grant types
    GRANT_TYPE_CHOICES = (
        ('authorization_code', _('Authorization Code')),
        ('implicit', _('Implicit')),
        ('password', _('Resource Owner Password Credentials')),
        ('client_credentials', _('Client Credentials')),
        ('refresh_token', _('Refresh Token')),
    )
    allowed_grant_types = models.JSONField(_('allowed grant types'), default=list)
    
    # Relations
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='oauth2_clients',
        verbose_name=_('user')
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='oauth2_clients',
        null=True,  # Set to True if some clients may not be tenant-specific
        blank=True,
        verbose_name=_('tenant')
    )
    
    # Redirection settings
    redirect_uris = models.JSONField(_('redirect URIs'), default=list)
    post_logout_redirect_uris = models.JSONField(_('post logout redirect URIs'), default=list)
    
    # Scopes
    allowed_scopes = models.JSONField(_('allowed scopes'), default=list)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    is_active = models.BooleanField(_('active'), default=True)
    description = models.TextField(_('description'), blank=True)
    logo_url = models.URLField(_('logo URL'), blank=True)
    website_url = models.URLField(_('website URL'), blank=True)
    privacy_policy_url = models.URLField(_('privacy policy URL'), blank=True)
    terms_of_service_url = models.URLField(_('terms of service URL'), blank=True)
    
    # JWT settings
    jwt_algorithm = models.CharField(_('JWT algorithm'), max_length=10, default='HS256')
    access_token_lifetime = models.PositiveIntegerField(_('access token lifetime in seconds'), default=3600)
    refresh_token_lifetime = models.PositiveIntegerField(_('refresh token lifetime in seconds'), default=604800)  # 7 days
    
    class Meta:
        verbose_name = _('OAuth2 client')
        verbose_name_plural = _('OAuth2 clients')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.client_id})"
    
    def save(self, *args, **kwargs):
        # Generate client_id and client_secret on first save
        if not self.client_id:
            self.client_id = uuid.uuid4().hex
        
        if not self.client_secret and self.client_type == 'confidential':
            self.client_secret = secrets.token_urlsafe(64)
            
        super().save(*args, **kwargs)
    
    def is_valid_redirect_uri(self, redirect_uri):
        """
        Check if the provided redirect URI is in the list of allowed redirect URIs.
        """
        return redirect_uri in self.redirect_uris
    
    def is_valid_scope(self, scope):
        """
        Check if the provided scope is in the list of allowed scopes.
        """
        requested_scopes = scope.split()
        return all(s in self.allowed_scopes for s in requested_scopes)


class OAuth2AuthorizationCode(models.Model):
    """
    Model for OAuth2 authorization codes.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(_('code'), max_length=255, unique=True)
    
    # Relations
    client = models.ForeignKey(
        OAuth2Client, 
        on_delete=models.CASCADE, 
        related_name='authorization_codes',
        verbose_name=_('client')
    )
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='oauth2_authorization_codes',
        verbose_name=_('user')
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='oauth2_authorization_codes',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    
    # Authorization details
    redirect_uri = models.CharField(_('redirect URI'), max_length=2000)
    scope = models.TextField(_('scope'), blank=True)
    code_challenge = models.CharField(_('code challenge'), max_length=255, blank=True)
    code_challenge_method = models.CharField(_('code challenge method'), max_length=10, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'))
    is_used = models.BooleanField(_('used'), default=False)
    
    class Meta:
        verbose_name = _('OAuth2 authorization code')
        verbose_name_plural = _('OAuth2 authorization codes')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Code for {self.client.name} - {self.user.email}"
    
    def save(self, *args, **kwargs):
        # Generate code on first save
        if not self.code:
            self.code = secrets.token_urlsafe(64)
        
        # Set expiration if not already set
        if not self.expires_at:
            # Authorization codes typically expire in 10 minutes
            self.expires_at = timezone.now() + timezone.timedelta(minutes=10)
            
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """
        Check if the authorization code is valid (not expired and not used).
        """
        return not self.is_used and self.expires_at > timezone.now()
    
    def use(self):
        """
        Mark the authorization code as used.
        """
        self.is_used = True
        self.save(update_fields=['is_used'])


class OAuth2Token(models.Model):
    """
    Model for OAuth2 tokens (access and refresh tokens).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Token values
    access_token = models.CharField(_('access token'), max_length=255, unique=True, editable=False)
    refresh_token = models.CharField(_('refresh token'), max_length=255, unique=True, null=True, blank=True, editable=False)
    
    # Token type
    TOKEN_TYPE_CHOICES = (
        ('bearer', _('Bearer')),
        ('mac', _('MAC')),
    )
    token_type = models.CharField(_('token type'), max_length=10, choices=TOKEN_TYPE_CHOICES, default='bearer')
    
    # Relations
    client = models.ForeignKey(
        OAuth2Client, 
        on_delete=models.CASCADE, 
        related_name='tokens',
        verbose_name=_('client')
    )
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='oauth2_tokens',
        verbose_name=_('user')
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='oauth2_tokens',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    
    # Token details
    scope = models.TextField(_('scope'), blank=True)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    access_token_expires_at = models.DateTimeField(_('access token expires at'))
    refresh_token_expires_at = models.DateTimeField(_('refresh token expires at'), null=True, blank=True)
    revoked_at = models.DateTimeField(_('revoked at'), null=True, blank=True)
    
    # Client info
    client_ip = models.GenericIPAddressField(_('client IP'), null=True, blank=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    
    class Meta:
        verbose_name = _('OAuth2 token')
        verbose_name_plural = _('OAuth2 tokens')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Token for {self.client.name} - {self.user.email}"
    
    def save(self, *args, **kwargs):
        # Generate tokens on first save
        if not self.access_token:
            self.access_token = secrets.token_urlsafe(64)
            
        if not self.refresh_token and 'refresh_token' in self.client.allowed_grant_types:
            self.refresh_token = secrets.token_urlsafe(64)
        
        # Set expiration if not already set
        if not self.access_token_expires_at:
            # Default access token lifetime from client settings or 1 hour
            lifetime_seconds = getattr(self.client, 'access_token_lifetime', 3600)
            self.access_token_expires_at = timezone.now() + timezone.timedelta(seconds=lifetime_seconds)
            
        if not self.refresh_token_expires_at and self.refresh_token:
            # Default refresh token lifetime from client settings or 14 days
            lifetime_seconds = getattr(self.client, 'refresh_token_lifetime', 1209600)  # 14 days
            self.refresh_token_expires_at = timezone.now() + timezone.timedelta(seconds=lifetime_seconds)
            
        super().save(*args, **kwargs)
    
    def is_access_token_valid(self):
        """
        Check if the access token is valid (not expired and not revoked).
        """
        return not self.is_revoked() and self.access_token_expires_at > timezone.now()
    
    def is_refresh_token_valid(self):
        """
        Check if the refresh token is valid (not expired and not revoked).
        """
        if not self.refresh_token or not self.refresh_token_expires_at:
            return False
            
        return not self.is_revoked() and self.refresh_token_expires_at > timezone.now()
    
    def is_revoked(self):
        """
        Check if the token has been revoked.
        """
        return self.revoked_at is not None
    
    def revoke(self):
        """
        Revoke the token.
        """
        self.revoked_at = timezone.now()
        self.save(update_fields=['revoked_at'])