# api_keys/authentication.py

from rest_framework import authentication
from rest_framework import exceptions
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .models import APIKey, APIKeyUsage

class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class for API key authentication.
    """
    
    def authenticate(self, request):
        """
        Authenticate the request and return a tuple of (user, auth_token).
        """
        # Get API key from header or query param
        api_key_value = self._get_api_key_from_request(request)
        
        if not api_key_value:
            return None  # No API key provided, let another auth method handle it
        
        # Find matching API key
        try:
            # Split the prefix from the rest of the key
            if len(api_key_value) < 9:  # prefix length + at least 1 char
                raise exceptions.AuthenticationFailed(_('Invalid API key'))
            
            prefix = api_key_value[:8]
            
            # Look up the API key by prefix
            api_key = APIKey.objects.select_related('user').get(prefix=prefix, is_active=True)
            
            # Verify the full key using constant-time comparison
            from django.utils.crypto import constant_time_compare
            if not constant_time_compare(api_key.key, api_key_value):
                raise exceptions.AuthenticationFailed(_('Invalid API key'))
            
            # Check if key is expired
            if api_key.expires_at and api_key.expires_at < timezone.now():
                raise exceptions.AuthenticationFailed(_('API key has expired'))
            
            # Check IP restrictions
            if hasattr(request, 'META') and 'REMOTE_ADDR' in request.META:
                client_ip = request.META['REMOTE_ADDR']
                if not api_key.is_allowed_ip(client_ip):
                    raise exceptions.AuthenticationFailed(_('API key not allowed from this IP address'))
            
            # Check referer restrictions
            if hasattr(request, 'META') and 'HTTP_REFERER' in request.META:
                referer = request.META['HTTP_REFERER']
                if not api_key.is_allowed_referer(referer):
                    raise exceptions.AuthenticationFailed(_('API key not allowed from this referer'))
            
            # Check rate limits
            if not api_key.check_rate_limit():
                raise exceptions.Throttled(detail=_('API key rate limit exceeded'))
            
            # Update last used timestamp
            api_key.update_last_used()
            
            # Log this usage
            self._log_api_key_usage(request, api_key)
            
            # Return authenticated user and API key
            return (api_key.user, api_key)
            
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid API key'))
    
    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the WWW-Authenticate header.
        """
        return 'Bearer'
    
    def _get_api_key_from_request(self, request):
        """
        Extract the API key from either the Authorization header or query parameter.
        """
        # Check Authorization header
        auth_header = authentication.get_authorization_header(request).decode('utf-8')
        if auth_header.startswith('Bearer '):
            return auth_header.split(' ')[1]
        
        # Check query parameter
        api_key = request.GET.get('api_key')
        if api_key:
            return api_key
        
        return None
    
    def _log_api_key_usage(self, request, api_key):
        """
        Log usage of the API key.
        """
        # Extract metadata from request
        method = request.method
        endpoint = request.path
        ip_address = request.META.get('REMOTE_ADDR', None)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Create usage log entry
        APIKeyUsage.objects.create(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            ip_address=ip_address,
            user_agent=user_agent
        )