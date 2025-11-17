"""
Permission utilities and decorators for RBAC enforcement.
"""
from functools import wraps
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework import status


class HasPermission(permissions.BasePermission):
    """
    Permission class that checks if user has a specific permission.
    Usage: permission_classes = [IsAuthenticated, HasPermission('users.change_profile')]
    """
    
    def __init__(self, permission_codename):
        self.permission_codename = permission_codename
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        return request.user.has_perm(self.permission_codename, request.tenant)


def permission_required(permission_codename):
    """
    Decorator that checks if user has a specific permission.
    
    Usage:
    @permission_required('users.change_profile')
    def my_view(request):
        # View code here
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {"error": "Authentication required."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            if not request.user.has_perm(permission_codename, request.tenant):
                return Response(
                    {"error": f"Permission denied. Required permission: {permission_codename}"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator


def check_permission(user, permission_codename, tenant):
    """
    Helper function to check if a user has a specific permission.
    
    Args:
        user: User instance
        permission_codename: Permission codename to check
        tenant: Tenant instance
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    if not user.is_authenticated:
        return False
    
    return user.has_perm(permission_codename, tenant)


class TenantPermissionMixin:
    """
    Mixin for ViewSets that adds permission checking for tenant-scoped permissions.
    """
    
    permission_map = {
        'list': None,
        'retrieve': None,
        'create': None,
        'update': None,
        'partial_update': None,
        'destroy': None,
    }
    
    def get_required_permission(self, action=None):
        """Get the required permission for the current action"""
        if action is None:
            action = self.action
        return self.permission_map.get(action)
    
    def check_permissions(self, request):
        """Override to add permission checking"""
        # First run the default permission checks
        super().check_permissions(request)
        
        # Then check specific permission for this action
        required_permission = self.get_required_permission()
        if required_permission and not request.user.has_perm(required_permission, request.tenant):
            self.permission_denied(
                request, 
                message=f"Permission denied. Required permission: {required_permission}"
            )


# Predefined permission classes for common use cases
class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Permission that allows read access to all authenticated users,
    but write access only to admin users.
    """
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Read permissions for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for admin users
        return request.user.has_role('admin', request.tenant)


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission that allows access only to the owner of the object or admin users.
    The object must have a 'user' field that links to the owner.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users can access everything
        if request.user.has_role('admin', request.tenant):
            return True
        
        # Object owner can access their own objects
        return hasattr(obj, 'user') and obj.user == request.user