# apps/authentication/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid

User = get_user_model()

class PasswordResetToken(models.Model):
    user = models.ForeignKey('users.User', on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    def __str__(self):
        return f"Reset token for {self.user.email}"

class UserSession(models.Model):
    """Track active JWT sessions for users"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    
    # JWT token info
    jti = models.CharField(max_length=255, unique=True, help_text="JWT ID (jti claim)")
    refresh_jti = models.CharField(max_length=255, unique=True, help_text="Refresh token JTI")
    
    # Session metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_name = models.CharField(max_length=255, blank=True, help_text="Device/browser name")
    location = models.CharField(max_length=255, blank=True, help_text="Geographic location")
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(help_text="When the refresh token expires")
    
    # Status
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=100, blank=True)
    
    class Meta:
        ordering = ['-last_used_at']
        indexes = [
            models.Index(fields=['user', '-last_used_at']),
            models.Index(fields=['jti']),
            models.Index(fields=['refresh_jti']),
            models.Index(fields=['is_active', '-last_used_at']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.device_name or 'Unknown Device'}"
    
    def revoke(self, reason='manual'):
        """Revoke this session"""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revoked_reason = reason
        self.save(update_fields=['is_active', 'revoked_at', 'revoked_reason'])
    
    def is_expired(self):
        """Check if session is expired"""
        return timezone.now() > self.expires_at
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used_at = timezone.now()
        self.save(update_fields=['last_used_at'])
    
    @classmethod
    def create_session(cls, user, tenant, jti, refresh_jti, expires_at, 
                      request=None, device_name=''):
        """
        Create a new session record
        
        Args:
            user: User instance
            tenant: Tenant instance
            jti: Access token JTI
            refresh_jti: Refresh token JTI
            expires_at: When refresh token expires
            request: Django request object (optional)
            device_name: Device/browser name
        """
        # Extract request metadata
        ip_address = None
        user_agent = ''
        location = ''
        
        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:1000]
            # You could add geolocation logic here
            location = ''  # Placeholder for geolocation
            
            # Try to detect device name from user agent
            if not device_name:
                device_name = cls._parse_device_name(user_agent)
        
        return cls.objects.create(
            user=user,
            tenant=tenant,
            jti=jti,
            refresh_jti=refresh_jti,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=device_name,
            location=location
        )
    
    @classmethod
    def get_by_jti(cls, jti):
        """Get active session by JTI"""
        try:
            return cls.objects.get(jti=jti, is_active=True)
        except cls.DoesNotExist:
            return None
    
    @classmethod
    def get_by_refresh_jti(cls, refresh_jti):
        """Get active session by refresh JTI"""
        try:
            return cls.objects.get(refresh_jti=refresh_jti, is_active=True)
        except cls.DoesNotExist:
            return None
    
    @classmethod
    def revoke_by_jti(cls, jti, reason='token_revoked'):
        """Revoke session by JTI"""
        try:
            session = cls.objects.get(jti=jti, is_active=True)
            session.revoke(reason)
            return True
        except cls.DoesNotExist:
            return False
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Remove expired sessions"""
        expired_count = cls.objects.filter(
            expires_at__lt=timezone.now()
        ).update(
            is_active=False,
            revoked_at=timezone.now(),
            revoked_reason='expired'
        )
        return expired_count
    
    @staticmethod
    def _get_client_ip(request):
        """Get the client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    
    @staticmethod
    def _parse_device_name(user_agent):
        """Parse device name from user agent"""
        user_agent = user_agent.lower()
        
        # Simple device detection
        if 'mobile' in user_agent or 'android' in user_agent:
            if 'android' in user_agent:
                return 'Android Device'
            return 'Mobile Device'
        elif 'iphone' in user_agent or 'ipad' in user_agent:
            if 'iphone' in user_agent:
                return 'iPhone'
            return 'iPad'
        elif 'windows' in user_agent:
            return 'Windows PC'
        elif 'macintosh' in user_agent or 'mac os' in user_agent:
            return 'Mac'
        elif 'linux' in user_agent:
            return 'Linux PC'
        else:
            return 'Unknown Device'