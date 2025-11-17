# apps/roles/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import json

User = get_user_model()

class Permission(models.Model):
    """Custom permission model for tenant-isolated RBAC"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    codename = models.CharField(max_length=100, help_text="Permission identifier (e.g., 'users.change_profile')")
    name = models.CharField(max_length=255, help_text="Human readable permission name")
    description = models.TextField(blank=True, help_text="Optional description of what this permission allows")
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='permissions')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('codename', 'tenant')
        ordering = ['codename']

    def __str__(self):
        return f"{self.codename} ({self.tenant})"

class Role(models.Model):
    """Role model with tenant isolation and delegation capabilities"""
    
    ROLE_LEVELS = [
        ('global_admin', 'Global Admin'),      # Full access across platform
        ('tenant_admin', 'Tenant Admin'),      # Full tenant access
        ('billing_manager', 'Billing Manager'), # Billing and subscription access
        ('auditor', 'Auditor'),                # Read-only audit access
        ('user_manager', 'User Manager'),       # User management only
        ('developer', 'Developer'),            # API and technical access
        ('user', 'User'),                      # Basic user access
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, help_text="Role name (e.g., 'admin', 'user')")
    level = models.CharField(max_length=20, choices=ROLE_LEVELS, default='user')
    description = models.TextField(blank=True, help_text="Optional role description")
    is_system = models.BooleanField(default=False, help_text="System roles cannot be deleted")
    is_delegatable = models.BooleanField(default=False, help_text="Can this role be assigned by non-admins")
    delegation_scope = models.JSONField(
        default=dict, 
        help_text="Scope restrictions for role delegation: {'departments': ['IT', 'HR'], 'max_users': 10}"
    )
    
    # ABAC Attributes
    abac_rules = models.JSONField(
        default=dict,
        help_text="ABAC rules: {'user.department': 'IT', 'user.location': 'US', 'resource.sensitivity': 'low'}"
    )
    
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='roles')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('name', 'tenant')
        ordering = ['level', 'name']

    def __str__(self):
        return f"{self.name} ({self.level}) - {self.tenant}"
    
    def can_delegate_to_user(self, delegator_user, target_user):
        """Check if a user can delegate this role to another user based on ABAC rules"""
        if not self.is_delegatable:
            return False, "Role is not delegatable"
        
        # Check delegation scope restrictions
        scope = self.delegation_scope
        
        if 'departments' in scope:
            if not hasattr(target_user, 'department') or target_user.department not in scope['departments']:
                return False, f"User department not in allowed scope: {scope['departments']}"
        
        if 'max_users' in scope:
            current_assignments = UserRole.objects.filter(role=self).count()
            if current_assignments >= scope['max_users']:
                return False, f"Maximum user limit reached: {scope['max_users']}"
        
        # Check ABAC rules
        for attribute, required_value in self.abac_rules.items():
            if '.' in attribute:
                obj_name, attr_name = attribute.split('.', 1)
                if obj_name == 'user':
                    user_value = getattr(target_user, attr_name, None)
                    if user_value != required_value:
                        return False, f"ABAC rule failed: {attribute} = {user_value} != {required_value}"
        
        return True, "OK"

class RolePermission(models.Model):
    """M2M through table for Role-Permission relationship"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='role_permissions')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('role', 'permission', 'tenant')

    def __str__(self):
        return f"{self.role.name} -> {self.permission.codename}"

class UserRole(models.Model):
    """User-Role assignment with tenant isolation and delegation tracking"""
    
    ASSIGNMENT_SOURCES = [
        ('admin', 'Admin Assignment'),
        ('delegation', 'Delegated Assignment'), 
        ('self_service', 'Self-Service'),
        ('jit', 'Just-in-Time'),
        ('import', 'Data Import'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_roles')
    
    # Enhanced delegation tracking
    assignment_source = models.CharField(max_length=20, choices=ASSIGNMENT_SOURCES, default='admin')
    delegation_chain = models.JSONField(
        default=list,
        help_text="Chain of delegation: [{'user_id': 'uuid', 'timestamp': 'iso'}, ...]"
    )
    
    # Time-based assignments
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Optional role expiration")
    is_active = models.BooleanField(default=True)
    
    # Conditional assignments based on ABAC
    conditions = models.JSONField(
        default=dict,
        help_text="Conditions for role activation: {'time_range': '09:00-17:00', 'ip_range': '192.168.1.0/24'}"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='revoked_roles')

    class Meta:
        unique_together = ('user', 'role', 'tenant')

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.user.email} -> {self.role.name} ({self.tenant}) [{status}]"
    
    def is_currently_valid(self):
        """Check if role assignment is currently valid based on conditions"""
        if not self.is_active or self.revoked_at:
            return False
            
        # Check expiration
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        
        # Check time-based conditions
        if 'time_range' in self.conditions:
            from datetime import time
            now = timezone.now().time()
            start_time, end_time = self.conditions['time_range'].split('-')
            start = time.fromisoformat(start_time)
            end = time.fromisoformat(end_time)
            if not (start <= now <= end):
                return False
        
        return True


class RoleDelegation(models.Model):
    """Track role delegation permissions and limits"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    delegator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delegations_granted')
    delegate = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delegations_received')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='delegations')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    
    # Delegation constraints
    max_assignments = models.IntegerField(default=10, help_text="Maximum number of users delegate can assign this role to")
    allowed_departments = models.JSONField(default=list, help_text="Departments delegate can assign role within")
    expires_at = models.DateTimeField(help_text="When delegation expires")
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='revoked_delegations')

    class Meta:
        unique_together = ('delegator', 'delegate', 'role', 'tenant')
        verbose_name = 'Role Delegation'
        verbose_name_plural = 'Role Delegations'

    def __str__(self):
        return f"{self.delegator.email} delegates {self.role.name} to {self.delegate.email}"
    
    def can_assign_to_user(self, target_user):
        """Check if this delegation allows assignment to target user"""
        if not self.is_active or self.revoked_at:
            return False, "Delegation is inactive"
        
        if timezone.now() > self.expires_at:
            return False, "Delegation has expired"
        
        # Check assignment limits
        assignments_count = UserRole.objects.filter(
            role=self.role,
            assigned_by=self.delegate,
            assignment_source='delegation'
        ).count()
        
        if assignments_count >= self.max_assignments:
            return False, f"Maximum assignments reached: {self.max_assignments}"
        
        # Check department restrictions
        if self.allowed_departments and hasattr(target_user, 'department'):
            if target_user.department not in self.allowed_departments:
                return False, f"User department {target_user.department} not in allowed list"
        
        return True, "OK"