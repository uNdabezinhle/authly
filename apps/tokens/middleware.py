import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from .models import ScopedToken

User = get_user_model()


class ScopedTokenMiddleware(MiddlewareMixin):
    """Middleware to validate scoped tokens and enforce permissions"""
    
    def process_request(self, request):
        # Skip for certain paths
        skip_paths = ['/admin/', '/api/docs/', '/api/schema/', '/api/auth/login/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Only process API requests
        if not request.path.startswith('/api/'):
            return None
        
        # Check for Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return None
        
        token_string = auth_header.split(' ')[1]
        
        try:
            # Decode JWT token
            payload = jwt.decode(
                token_string,
                settings.SECRET_KEY,
                algorithms=['HS256'],
                options={'verify_exp': True}
            )
            
            jti = payload.get('jti')
            if not jti:
                return JsonResponse({'error': 'Invalid token: missing JTI'}, status=401)
            
            # Look up token in database
            try:
                scoped_token = ScopedToken.objects.select_related('user', 'tenant').get(jti=jti)
            except ScopedToken.DoesNotExist:
                return JsonResponse({'error': 'Token not found'}, status=401)
            
            # Validate token
            if not scoped_token.is_valid():
                return JsonResponse({'error': 'Token is invalid or expired'}, status=401)
            
            # Record usage
            client_ip = self.get_client_ip(request)
            scoped_token.record_usage(client_ip)
            
            # Set user and tenant on request
            request.user = scoped_token.user
            request.tenant = scoped_token.tenant
            request.scoped_token = scoped_token
            
            # Store token claims for permission checking
            request.token_scopes = payload.get('scopes', [])
            request.token_permissions = payload.get('permissions', [])
            
            return None
            
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        except Exception as e:
            return JsonResponse({'error': 'Token validation failed'}, status=401)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class ScopePermission:
    """Permission class for checking token scopes"""
    
    def __init__(self, required_scopes=None, required_permissions=None):
        self.required_scopes = required_scopes or []
        self.required_permissions = required_permissions or []
    
    def has_permission(self, request, view):
        # If no scoped token, fall back to regular authentication
        if not hasattr(request, 'scoped_token'):
            return True
        
        token_scopes = getattr(request, 'token_scopes', [])
        token_permissions = getattr(request, 'token_permissions', [])
        
        # Check required scopes
        for scope in self.required_scopes:
            if scope not in token_scopes:
                return False
        
        # Check required permissions
        for permission in self.required_permissions:
            if permission not in token_permissions:
                return False
        
        return True


def require_scopes(*scopes):
    """Decorator to require specific scopes"""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if hasattr(request, 'scoped_token'):
                token_scopes = getattr(request, 'token_scopes', [])
                for scope in scopes:
                    if scope not in token_scopes:
                        return JsonResponse({
                            'error': f'Required scope missing: {scope}',
                            'required_scopes': list(scopes),
                            'token_scopes': token_scopes
                        }, status=403)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_permissions(*permissions):
    """Decorator to require specific permissions"""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if hasattr(request, 'scoped_token'):
                token_permissions = getattr(request, 'token_permissions', [])
                for permission in permissions:
                    if permission not in token_permissions:
                        return JsonResponse({
                            'error': f'Required permission missing: {permission}',
                            'required_permissions': list(permissions),
                            'token_permissions': token_permissions
                        }, status=403)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator