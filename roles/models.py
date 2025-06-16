# roles/models.py

import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from mptt.models import MPTTModel, TreeForeignKey

User = get_user_model()

class Permission(models.Model):
    """
    Model for a permission that can be assigned to roles.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255, unique=True)
    description = models.TextField(_('description'), blank=True)
    codename = models.CharField(_('codename'), max_length=100, unique=True)
    resource = models.CharField(_('resource'), max_length=100)
    action = models.CharField(_('action'), max_length=100)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')
        ordering = ['resource', 'action']
        unique_together = ('resource', 'action')
    
    def __str__(self):
        return f"{self.name} ({self.codename})"
    
    def save(self, *args, **kwargs):
        # Auto-generate codename if not provided
        if not self.codename:
            self.codename = f"{self.resource}:{self.action}"
        super().save(*args, **kwargs)


class Role(MPTTModel):
    """
    Model for a role that can be assigned to users and groups. Uses MPTT for hierarchical roles.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255)
    description = models.TextField(_('description'), blank=True)
    
    # Hierarchical relationship - for role inheritance
    parent = TreeForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, 
                           related_name='children', verbose_name=_('parent'))
    
    # Many-to-many relationship with permissions
    permissions = models.ManyToManyField(
        Permission, 
        verbose_name=_('permissions'),
        blank=True,
        related_name='roles'
    )
    
    # System role flag - can't be deleted
    is_system_role = models.BooleanField(_('system role'), default=False)
    
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('role')
        verbose_name_plural = _('roles')
        unique_together = ('name', 'parent')
    
    class MPTTMeta:
        order_insertion_by = ['name']
    
    def __str__(self):
        return self.name
    
    def get_all_permissions(self):
        """
        Get all permissions for this role including inherited permissions from parent roles.
        """
        # Start with this role's direct permissions
        permission_set = set(self.permissions.all())
        
        # Add parent roles' permissions
        if self.parent:
            permission_set.update(self.parent.get_all_permissions())
            
        return permission_set


class Group(models.Model):
    """
    Model for a group of users that can be assigned roles collectively.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255, unique=True)
    description = models.TextField(_('description'), blank=True)
    
    # Many-to-many relationships
    users = models.ManyToManyField(User, verbose_name=_('users'), blank=True, related_name='role_groups')
    roles = models.ManyToManyField(Role, verbose_name=_('roles'), blank=True, related_name='groups')
    
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('group')
        verbose_name_plural = _('groups')
        ordering = ['name']
    
    def __str__(self):
        return self.name


class UserRole(models.Model):
    """
    Model for storing the many-to-many relationship between users and roles with additional metadata.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    
    # Metadata
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='assigned_roles'
    )
    assigned_at = models.DateTimeField(_('assigned at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True)
    
    class Meta:
        verbose_name = _('user role')
        verbose_name_plural = _('user roles')
        unique_together = ('user', 'role')
    
    def __str__(self):
        return f"{self.user.email} - {self.role.name}"
    
    def is_active(self):
        """
        Check if the role assignment is still active (not expired).
        """
        if self.expires_at is None:
            return True
        from django.utils import timezone
        return self.expires_at > timezone.now()


class ABACRule(models.Model):
    """
    Model for Attribute-Based Access Control (ABAC) rules.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=255, unique=True)
    description = models.TextField(_('description'), blank=True)
    resource = models.CharField(_('resource'), max_length=100)
    action = models.CharField(_('action'), max_length=100)
    
    # JSON fields for the rule conditions
    user_attribute_conditions = models.JSONField(_('user attribute conditions'), default=dict, blank=True)
    resource_attribute_conditions = models.JSONField(_('resource attribute conditions'), default=dict, blank=True)
    environment_conditions = models.JSONField(_('environment conditions'), default=dict, blank=True)
    
    # Priority for rule evaluation order
    priority = models.PositiveIntegerField(_('priority'), default=0)
    
    # Effect of the rule
    effect = models.CharField(_('effect'), max_length=10, choices=(
        ('allow', _('Allow')),
        ('deny', _('Deny')),
    ), default='allow')
    
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('ABAC rule')
        verbose_name_plural = _('ABAC rules')
        ordering = ['priority', 'resource', 'action']
    
    def __str__(self):
        return f"{self.name} ({self.effect} {self.resource}:{self.action})"