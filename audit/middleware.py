# audit/middleware.py

import logging
import json
from django.utils.deprecation import MiddlewareMixin
from django.urls import resolve
from django.utils import timezone
from .models import AuditLog

logger = logging.getLogger('audit')

class AuditMiddleware(MiddlewareMixin):
    """
    Middleware for logging audit events automatically.
    """
    
    def process_request(self, request):
        """
        Process the request and store it in the request object for later use.
        """
        # Store the request start time
        request.audit_start_time = timezone.now()
        
        # Add info to the request that will be used for auditing
        request.audit_info = {
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'method': request.method,
            'path': request.path,
        }
    
    def process_response(self, request, response):
        """
        Process the response and log any relevant audit events.
        """
        # Skip if this is a static file or media file request
        if hasattr(request, 'audit_info') and not self._is_static_request(request):
            # Add response info
            request.audit_info['status_code'] = response.status_code
            request.audit_info['response_time'] = (timezone.now() - request.audit_start_time).total_seconds() * 1000
            
            # Log authentication events
            self._log_authentication_events(request, response)
            
            # Log API key usage events
            self._log_api_key_events(request, response)
            
            # Log resource access events for sensitive or critical resources
            self._log_resource_access_events(request, response)
        
        return response
    
    def _get_client_ip(self, request):
        """
        Get the client IP address from the request.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can be a comma-separated list of IPs.
            # The client's IP will be the first one.
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _is_static_request(self, request):
        """
        Check if the request is for a static file or media file.
        """
        path = request.path
        return path.startswith('/static/') or path.startswith('/media/')
    
    def _log_authentication_events(self, request, response):
        """
        Log authentication-related events.
        """
        path = request.path
        method = request.method
        
        # Detect login events
        if path.endswith('/auth/login/') and method == 'POST':
            event_type = 'login_success' if response.status_code in (200, 201, 204) else 'login_failure'
            self._create_audit_log(request, event_type, 'auth', success=(event_type == 'login_success'))
        
        # Detect logout events
        elif path.endswith('/auth/logout/') and method in ('POST', 'GET'):
            self._create_audit_log(request, 'logout', 'auth', success=True)
        
        # Detect password reset events
        elif path.endswith('/auth/password/reset/') and method == 'POST':
            self._create_audit_log(request, 'password_reset_request', 'auth', success=(response.status_code in (200, 201, 204)))
        
        # Detect password reset confirmation events
        elif path.endswith('/auth/password/reset/confirm/') and method == 'POST':
            self._create_audit_log(request, 'password_reset_complete', 'auth', success=(response.status_code in (200, 201, 204)))
        
        # Detect password change events
        elif path.endswith('/auth/password/change/') and method == 'POST':
            self._create_audit_log(request, 'password_change', 'auth', success=(response.status_code in (200, 201, 204)))
        
        # Detect 2FA events
        elif path.endswith('/auth/2fa/enable/') and method == 'POST':
            self._create_audit_log(request, '2fa_enabled', 'auth', success=(response.status_code in (200, 201, 204)))
        
        elif path.endswith('/auth/2fa/disable/') and method == 'POST':
            self._create_audit_log(request, '2fa_disabled', 'auth', success=(response.status_code in (200, 201, 204)))
        
        elif path.endswith('/auth/2fa/verify/') and method == 'POST':
            event_type = '2fa_success' if response.status_code in (200, 201, 204) else '2fa_failure'
            self._create_audit_log(request, event_type, 'auth', success=(event_type == '2fa_success'))
    
    def _log_api_key_events(self, request, response):
        """
        Log API key related events.
        """
        # Check if the request was authenticated using an API key
        if hasattr(request, 'auth') and hasattr(request.auth, 'prefix') and hasattr(request.auth, 'key'):
            # This is an API key authenticated request
            self._create_audit_log(
                request,
                'api_key_used',
                'api_key',
                success=(response.status_code < 400),
                details={'api_key_prefix': request.auth.prefix}
            )
    
    def _log_resource_access_events(self, request, response):
        """
        Log access to sensitive or critical resources.
        """
        # Resolve the URL to get the view function
        try:
            resolver_match = resolve(request.path)
            view_name = resolver_match.view_name
            
            # Define sensitive views
            sensitive_views = [
                'user-detail', 'user-list',
                'role-detail', 'role-list',
                'permission-detail', 'permission-list',
                'api-key-detail', 'api-key-list',
                'oauth2-client-detail', 'oauth2-client-list',
            ]
            
            if view_name in sensitive_views:
                event_type = 'access_granted' if response.status_code < 400 else 'access_denied'
                
                self._create_audit_log(
                    request,
                    event_type,
                    'authorization',
                    success=(event_type == 'access_granted'),
                    details={
                        'view_name': view_name,
                        'parameters': resolver_match.kwargs
                    }
                )
        except:
            # If URL resolution fails, don't log this as a resource access
            pass
    
    def _create_audit_log(self, request, event_type, category, success=True, details=None):
        """
        Create and save an audit log entry.
        """
        # Base details
        log_details = details or {}
        log_details.update({
            'method': request.method,
            'path': request.path,
            'status_code': request.audit_info.get('status_code'),
            'response_time': request.audit_info.get('response_time'),
        })
        
        # Add request body for login and other sensitive operations, but exclude passwords
        if event_type in ['login_success', 'login_failure', 'password_reset_request', 'password_reset_complete']:
            try:
                body = request.data if hasattr(request, 'data') else {}
                # Remove sensitive information
                if isinstance(body, dict):
                    if 'password' in body:
                        body['password'] = '********'
                    if 'new_password' in body:
                        body['new_password'] = '********'
                    if 'confirm_password' in body:
                        body['confirm_password'] = '********'
                    log_details['request_data'] = body
            except:
                pass
        
        # Create the log entry
        try:
            AuditLog.objects.create(
                event_type=event_type,
                category=category,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.audit_info.get('ip_address'),
                user_agent=request.audit_info.get('user_agent'),
                details=log_details,
                success=success
            )
            
            # Also log to the audit logger
            log_message = f"{event_type} - User: {request.user.email if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous'} - Path: {request.path}"
            if success:
                logger.info(log_message)
            else:
                logger.warning(log_message)
                
        except Exception as e:
            # Make sure audit logging errors don't break the application
            logger.error(f"Error creating audit log: {str(e)}")