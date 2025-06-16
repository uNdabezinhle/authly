from django.contrib import admin
from .models import Permission, Role, Group, UserRole, ABACRule

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('name', 'codename', 'resource', 'action', 'tenant')
    list_filter = ('tenant', 'resource', 'action')

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent', 'is_system_role', 'tenant')
    list_filter = ('tenant', 'is_system_role')

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant')
    list_filter = ('tenant',)

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'assigned_by', 'assigned_at', 'tenant')
    list_filter = ('tenant', 'role')

@admin.register(ABACRule)
class ABACRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'resource', 'action', 'effect', 'priority', 'is_active', 'tenant')
    list_filter = ('tenant', 'resource', 'action', 'effect', 'is_active')
