# roles/serializers.py

from rest_framework import serializers
from .models import Permission, Role, Group, UserRole, ABACRule

class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Permission model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = Permission
        fields = ['id', 'tenant', 'name', 'codename', 'resource', 'action']

class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the Role model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'tenant', 'name', 'parent', 'permissions', 'is_system_role']

class RoleDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the Role model, including child roles.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    permissions = PermissionSerializer(many=True, read_only=True)
    children = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'tenant', 'name', 'parent', 'permissions', 'is_system_role', 'children']

    def get_children(self, obj):
        return RoleSerializer(obj.get_children(), many=True).data

class RoleCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new roles.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'tenant', 'name', 'parent', 'permissions', 'is_system_role']

class RolePermissionAssignSerializer(serializers.Serializer):
    """
    Serializer for assigning permissions to a role.
    """
    permissions = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(), many=True
    )

class GroupSerializer(serializers.ModelSerializer):
    """
    Serializer for the Group model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = Group
        fields = ['id', 'tenant', 'name', 'roles']

class GroupDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the Group model, including role details.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    roles = RoleSerializer(many=True, read_only=True)

    class Meta:
        model = Group
        fields = ['id', 'tenant', 'name', 'roles']

class ABACRuleSerializer(serializers.ModelSerializer):
    """
    Serializer for the ABACRule model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = ABACRule
        fields = [
            'id', 'tenant', 'name', 'resource', 'action',
            'condition', 'effect', 'priority', 'is_active'
        ]

class UserRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserRole model (role assignments).
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = UserRole
        fields = [
            'id', 'tenant', 'user', 'role',
            'assigned_by', 'assigned_at'
        ]