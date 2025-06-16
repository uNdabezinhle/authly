# roles/models.py

import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from mptt.models import MPTTModel, TreeForeignKey
from tenants.models import Tenant
from django.conf import settings

class Permission(models.Model):
    """
    Model for a permission that can be assigned to roles.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='permissions',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    name = models.CharField(max_length=255)
    codename = models.CharField(max_length=100)
    resource = models.CharField(max_length=100)
    action = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.resource}:{self.action}"

class Role(MPTTModel):
    """
    Model for a role that can be assigned to users and groups. Uses MPTT for hierarchical roles.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='roles',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    name = models.CharField(max_length=255)
    parent = TreeForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    permissions = models.ManyToManyField(Permission, blank=True)
    is_system_role = models.BooleanField(default=False)

    class MPTTMeta:
        order_insertion_by = ['name']

    def __str__(self):
        return self.name

class Group(models.Model):
    """
    Model for a group of users that can be assigned roles collectively.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='groups',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    name = models.CharField(max_length=255)
    roles = models.ManyToManyField(Role, blank=True)

    def __str__(self):
        return self.name

class UserRole(models.Model):
    """
    Model for storing the many-to-many relationship between users and roles with additional metadata.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='user_roles',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_roles')
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.role}"

class ABACRule(models.Model):
    """
    Model for Attribute-Based Access Control (ABAC) rules.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='abac_rules',
        null=True,
        blank=True,
        verbose_name=_('tenant')
    )
    name = models.CharField(max_length=255)
    resource = models.CharField(max_length=100)
    action = models.CharField(max_length=100)
    condition = models.JSONField(default=dict)
    effect = models.CharField(max_length=10, choices=[('allow', 'Allow'), ('deny', 'Deny')])
    priority = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name