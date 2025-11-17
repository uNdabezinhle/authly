from rest_framework.permissions import BasePermission
from django.contrib.auth import get_user_model
from .models import Role, UserRole, RoleDelegation

User = get_user_model()


class IsTenantAdmin(BasePermission):
    """Permission class for tenant admin access"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check if user has tenant_admin role
        return UserRole.objects.filter(
            user=request.user,
            role__level='tenant_admin',
            is_active=True,
            revoked_at__isnull=True
        ).exists()


class IsBillingManager(BasePermission):
    """Permission class for billing manager access"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check if user has billing_manager or tenant_admin role
        return UserRole.objects.filter(
            user=request.user,
            role__level__in=['billing_manager', 'tenant_admin'],
            is_active=True,
            revoked_at__isnull=True
        ).exists()


class IsAuditor(BasePermission):
    """Permission class for auditor access (read-only)"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Auditors can only read
        if request.method not in ['GET', 'HEAD', 'OPTIONS']:
            return False
        
        return UserRole.objects.filter(
            user=request.user,
            role__level__in=['auditor', 'tenant_admin'],
            is_active=True,
            revoked_at__isnull=True
        ).exists()


class CanDelegateRole(BasePermission):
    """Permission class for role delegation"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Only allow POST for delegation
        if request.method != 'POST':
            return False
        
        role_id = request.data.get('role_id')
        if not role_id:
            return False
        
        try:
            role = Role.objects.get(id=role_id)
            
            # Check if user has delegation permission for this role
            has_delegation = RoleDelegation.objects.filter(
                delegate=request.user,
                role=role,
                is_active=True,
                revoked_at__isnull=True
            ).exists()
            
            # Or if user is tenant admin
            is_admin = UserRole.objects.filter(
                user=request.user,
                role__level='tenant_admin',
                is_active=True,
                revoked_at__isnull=True
            ).exists()
            
            return has_delegation or is_admin
            
        except Role.DoesNotExist:
            return False


class HasRequiredRole(BasePermission):
    """Generic permission class that checks for specific role levels"""
    
    required_roles = []  # Override in subclass
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return UserRole.objects.filter(
            user=request.user,
            role__level__in=self.required_roles,
            is_active=True,
            revoked_at__isnull=True
        ).exists()


class ABACPermission(BasePermission):
    """Attribute-Based Access Control permission"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Get user's active roles
        user_roles = UserRole.objects.filter(
            user=request.user,
            is_active=True,
            revoked_at__isnull=True
        ).select_related('role')
        
        # Check ABAC rules for each role
        for user_role in user_roles:
            if self.evaluate_abac_rules(request, user_role.role, request.user):
                return True
        
        return False
    
    def evaluate_abac_rules(self, request, role, user):
        """Evaluate ABAC rules for a role"""
        abac_rules = role.abac_rules
        
        if not abac_rules:
            return True  # No rules = allow access
        
        for attribute, required_value in abac_rules.items():
            if '.' in attribute:
                obj_name, attr_name = attribute.split('.', 1)
                
                if obj_name == 'user':
                    user_value = getattr(user, attr_name, None)
                    if user_value != required_value:
                        return False
                
                elif obj_name == 'request':
                    if attr_name == 'method' and request.method != required_value:
                        return False
                    elif attr_name == 'ip':
                        client_ip = self.get_client_ip(request)
                        if not self.ip_in_range(client_ip, required_value):
                            return False
                
                elif obj_name == 'time':
                    from datetime import time
                    from django.utils import timezone
                    
                    if attr_name == 'hour_range':
                        start_hour, end_hour = map(int, required_value.split('-'))
                        current_hour = timezone.now().hour
                        if not (start_hour <= current_hour <= end_hour):
                            return False
        
        return True
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    
    def ip_in_range(self, ip, ip_range):
        """Check if IP is in given range (CIDR notation)"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range, strict=False)
        except:
            return False


def tenant_admin_required(view_func):
    """Decorator to require tenant admin access"""
    def wrapper(request, *args, **kwargs):
        permission = IsTenantAdmin()
        if not permission.has_permission(request, None):
            from django.http import JsonResponse
            return JsonResponse({'error': 'Tenant admin access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def billing_manager_required(view_func):
    """Decorator to require billing manager access"""
    def wrapper(request, *args, **kwargs):
        permission = IsBillingManager()
        if not permission.has_permission(request, None):
            from django.http import JsonResponse
            return JsonResponse({'error': 'Billing manager access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def auditor_required(view_func):
    """Decorator to require auditor access"""
    def wrapper(request, *args, **kwargs):
        permission = IsAuditor()
        if not permission.has_permission(request, None):
            from django.http import JsonResponse
            return JsonResponse({'error': 'Auditor access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper