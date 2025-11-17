import uuid
import jwt
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

User = get_user_model()


class TokenScope(models.Model):
    """Define available scopes for tokens"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, help_text="Scope name (e.g., 'users.read')")
    description = models.TextField(help_text="Human readable description of what this scope allows")
    resource_type = models.CharField(max_length=50, help_text="Resource type (e.g., 'users', 'api_keys', 'audit')")
    actions = models.JSONField(
        default=list, 
        help_text="List of allowed actions: ['read', 'write', 'delete']"
    )
    
    # Scope constraints
    is_sensitive = models.BooleanField(default=False, help_text="Requires elevated permissions")
    requires_mfa = models.BooleanField(default=False, help_text="Requires MFA for token generation")
    max_token_lifetime = models.IntegerField(
        default=3600, 
        help_text="Maximum lifetime for tokens with this scope (seconds)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['resource_type', 'name']
        verbose_name = 'Token Scope'
        verbose_name_plural = 'Token Scopes'
    
    def __str__(self):
        return f"{self.name} ({self.resource_type})"


class ScopedToken(models.Model):
    """Scoped tokens with specific permissions and constraints"""
    
    TOKEN_TYPES = [
        ('access', 'Access Token'),
        ('refresh', 'Refresh Token'),
        ('api_key', 'API Key Token'),
        ('delegation', 'Delegated Token'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scoped_tokens')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='scoped_tokens')
    
    # Token identification
    jti = models.CharField(max_length=255, unique=True, help_text="JWT ID (unique token identifier)")
    token_type = models.CharField(max_length=20, choices=TOKEN_TYPES, default='access')
    
    # Scopes and permissions
    scopes = models.ManyToManyField(TokenScope, related_name='tokens')
    permissions = models.JSONField(
        default=list,
        help_text="Specific permissions granted: ['users.read', 'api_keys.write']"
    )
    
    # Token constraints
    audience = models.CharField(max_length=255, help_text="Intended audience for the token")
    client_id = models.CharField(max_length=255, blank=True, help_text="Client that requested the token")
    
    # Delegation support
    delegated_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='delegated_tokens',
        help_text="User who delegated this token"
    )
    delegation_chain = models.JSONField(
        default=list,
        help_text="Chain of delegation: [{'user_id': 'uuid', 'timestamp': 'iso'}]"
    )
    
    # Time and usage constraints
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    not_before = models.DateTimeField(default=timezone.now, help_text="Token not valid before this time")
    
    # Usage tracking
    usage_count = models.IntegerField(default=0)
    max_uses = models.IntegerField(null=True, blank=True, help_text="Maximum number of times token can be used")
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Token status
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='revoked_tokens'
    )
    revocation_reason = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-issued_at']
        verbose_name = 'Scoped Token'
        verbose_name_plural = 'Scoped Tokens'
        indexes = [
            models.Index(fields=['jti']),
            models.Index(fields=['user', 'tenant']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.token_type} token for {self.user.email} ({self.jti[:8]}...)"
    
    def is_valid(self):
        """Check if token is currently valid"""
        now = timezone.now()
        
        if not self.is_active or self.revoked_at:
            return False
        
        if now < self.not_before or now > self.expires_at:
            return False
        
        if self.max_uses and self.usage_count >= self.max_uses:
            return False
        
        return True
    
    def record_usage(self, ip_address=None):
        """Record token usage"""
        self.usage_count += 1
        self.last_used_at = timezone.now()
        if ip_address:
            self.last_used_ip = ip_address
        self.save(update_fields=['usage_count', 'last_used_at', 'last_used_ip'])
    
    def revoke(self, revoked_by=None, reason=""):
        """Revoke the token"""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revoked_by = revoked_by
        self.revocation_reason = reason
        self.save(update_fields=['is_active', 'revoked_at', 'revoked_by', 'revocation_reason'])
    
    def get_scope_names(self):
        """Get list of scope names for this token"""
        return list(self.scopes.values_list('name', flat=True))
    
    def has_scope(self, scope_name):
        """Check if token has a specific scope"""
        return self.scopes.filter(name=scope_name).exists()
    
    def has_permission(self, permission):
        """Check if token has a specific permission"""
        return permission in self.permissions
    
    def generate_jwt(self):
        """Generate JWT token with claims"""
        now = timezone.now()
        
        payload = {
            'iss': settings.JWT_ISSUER if hasattr(settings, 'JWT_ISSUER') else 'authly-api',
            'sub': str(self.user.id),
            'aud': self.audience,
            'iat': int(now.timestamp()),
            'exp': int(self.expires_at.timestamp()),
            'nbf': int(self.not_before.timestamp()),
            'jti': self.jti,
            
            # Custom claims
            'tenant_id': str(self.tenant.id),
            'token_type': self.token_type,
            'scopes': self.get_scope_names(),
            'permissions': self.permissions,
            'usage_count': self.usage_count,
        }
        
        if self.delegated_by:
            payload['delegated_by'] = str(self.delegated_by.id)
            payload['delegation_chain'] = self.delegation_chain
        
        if self.client_id:
            payload['client_id'] = self.client_id
        
        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )


class TokenIntrospection(models.Model):
    """Log token introspection requests for security monitoring"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.ForeignKey(ScopedToken, on_delete=models.CASCADE, related_name='introspections')
    requester_ip = models.GenericIPAddressField()
    requester_user_agent = models.TextField(blank=True)
    
    # Introspection details
    requested_at = models.DateTimeField(auto_now_add=True)
    was_valid = models.BooleanField()
    validation_reason = models.CharField(max_length=255, blank=True)
    
    # Additional context
    endpoint = models.CharField(max_length=255, blank=True)
    client_id = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-requested_at']
        verbose_name = 'Token Introspection'
        verbose_name_plural = 'Token Introspections'
    
    def __str__(self):
        return f"Introspection of {self.token.jti[:8]}... at {self.requested_at}"


class TokenRevocation(models.Model):
    """Track token revocations for audit purposes"""
    
    REVOCATION_REASONS = [
        ('user_request', 'User Request'),
        ('admin_revoke', 'Admin Revocation'),
        ('security_breach', 'Security Breach'),
        ('expired', 'Token Expired'),
        ('compromised', 'Token Compromised'),
        ('policy_violation', 'Policy Violation'),
        ('user_deactivated', 'User Deactivated'),
        ('tenant_suspended', 'Tenant Suspended'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.ForeignKey(ScopedToken, on_delete=models.CASCADE, related_name='revocation_logs')
    
    # Revocation details
    revoked_at = models.DateTimeField(auto_now_add=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    reason = models.CharField(max_length=20, choices=REVOCATION_REASONS)
    notes = models.TextField(blank=True)
    
    # Context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-revoked_at']
        verbose_name = 'Token Revocation'
        verbose_name_plural = 'Token Revocations'
    
    def __str__(self):
        return f"Revocation of {self.token.jti[:8]}... ({self.reason})"