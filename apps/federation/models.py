import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django_tenants.models import TenantMixin

User = get_user_model()


class IdentityProvider(models.Model):
    """Identity Provider configuration per tenant"""
    
    PROVIDER_TYPES = [
        ('saml', 'SAML 2.0'),
        ('oidc', 'OpenID Connect'),
        ('oauth2', 'OAuth 2.0'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('testing', 'Testing'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, help_text="Display name for IdP")
    slug = models.SlugField(unique=True, help_text="URL-friendly identifier")
    provider_type = models.CharField(max_length=10, choices=PROVIDER_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    
    # SAML Configuration
    entity_id = models.URLField(blank=True, help_text="SAML Entity ID")
    metadata_url = models.URLField(blank=True, help_text="SAML Metadata URL")
    sso_url = models.URLField(blank=True, help_text="SAML SSO URL")
    sls_url = models.URLField(blank=True, help_text="SAML Logout URL")
    x509_cert = models.TextField(blank=True, help_text="X.509 Certificate")
    sp_cert = models.TextField(blank=True, help_text="Service Provider Certificate")
    sp_private_key = models.TextField(blank=True, help_text="Service Provider Private Key")
    
    # OIDC Configuration  
    client_id = models.CharField(max_length=255, blank=True)
    client_secret = models.CharField(max_length=255, blank=True)
    authorization_endpoint = models.URLField(blank=True)
    token_endpoint = models.URLField(blank=True)
    userinfo_endpoint = models.URLField(blank=True)
    jwks_uri = models.URLField(blank=True)
    issuer = models.URLField(blank=True)
    
    # JIT Provisioning
    jit_enabled = models.BooleanField(default=False, help_text="Just-in-Time user provisioning")
    jit_default_role = models.CharField(max_length=50, default='user', help_text="Default role for JIT users")
    
    # Attribute Mapping
    attribute_mapping = models.JSONField(
        default=dict,
        help_text="Map IdP attributes to user fields: {'email': 'mail', 'first_name': 'givenName'}"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Identity Provider'
        verbose_name_plural = 'Identity Providers'
    
    def __str__(self):
        return f"{self.name} ({self.provider_type.upper()})"


class FederatedUser(models.Model):
    """Link between external IdP users and local users"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='federated_identities')
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE, related_name='federated_users')
    
    external_user_id = models.CharField(max_length=255, help_text="User ID from IdP")
    external_username = models.CharField(max_length=255, blank=True)
    external_email = models.EmailField(blank=True)
    
    # Store original attributes from IdP
    attributes = models.JSONField(default=dict, help_text="Original attributes from IdP")
    
    first_login = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = [['identity_provider', 'external_user_id']]
        verbose_name = 'Federated User'
        verbose_name_plural = 'Federated Users'
    
    def __str__(self):
        return f"{self.user.email} via {self.identity_provider.name}"


class SAMLSession(models.Model):
    """Track SAML authentication sessions"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.CharField(max_length=255, unique=True)
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    # SAML Request/Response tracking
    saml_request_id = models.CharField(max_length=255, blank=True)
    relay_state = models.TextField(blank=True)
    
    # Session status
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('authenticated', 'Authenticated'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    ], default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'SAML Session'
        verbose_name_plural = 'SAML Sessions'
    
    def __str__(self):
        return f"SAML Session {self.session_id[:8]}... ({self.status})"