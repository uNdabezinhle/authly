# roles/serializers.py

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import Role, Permission, Group, UserRole, ABACRule

class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Permission model.
    """
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description', 'codename', 'resource', 'action', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class PermissionLightSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for the Permission model (used in nested relationships).
    """
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename']

class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the Role model.
    """
    permissions = PermissionLightSerializer(many=True, read_only=True)
    parent_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'parent', 'parent_name', 'permissions', 
                 'is_system_role', 'created_at', 'updated_at']
        read_only_fields = ['id', 'is_system_role', 'created_at', 'updated_at']
    
    def get_parent_name(self, obj):
        if obj.parent:
            return obj.parent.name
        return None

class RoleDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the Role model with all permissions and hierarchy information.
    """
    permissions = PermissionLightSerializer(many=True, read_only=True)
    parent = RoleSerializer(read_only=True)
    children = serializers.SerializerMethodField()
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'parent', 'children', 'permissions', 
                 'is_system_role', 'created_at', 'updated_at', 'user_count']
        read_only_fields = ['id', 'created_at', 'updated_at', 'children', 'user_count']
    
    def get_children(self, obj):
        children = obj.get_children()
        return RoleSerializer(children, many=True).data
    
    def get_user_count(self, obj):
        return obj.user_roles.count()


class RoleCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new role.
    """
    class Meta:
        model = Role
        fields = ['name', 'description', 'parent']


class RolePermissionAssignSerializer(serializers.Serializer):
    """
    Serializer for assigning permissions to a role.
    """
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=True
    )


class GroupSerializer(serializers.ModelSerializer):
    """
    Serializer for the Group model.
    """
    roles = RoleSerializer(many=True, read_only=True)
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Group
        fields = ['id', 'name', 'description', 'roles', 'created_at', 'updated_at', 'user_count']
        read_only_fields = ['id', 'created_at', 'updated_at', 'user_count']
    
    def get_user_count(self, obj):
        return obj.users.count()


class GroupDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the Group model with all users and roles.
    """
    roles = RoleSerializer(many=True, read_only=True)
    users = serializers.SerializerMethodField()
    
    class Meta:
        model = Group
        fields = ['id', 'name', 'description', 'roles', 'users', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'users']
    
    def get_users(self, obj):
        from users.serializers import UserSerializer
        return UserSerializer(obj.users.all(), many=True).data


class ABACRuleSerializer(serializers.ModelSerializer):
    """
    Serializer for the ABACRule model.
    """
    class Meta:
        model = ABACRule
        fields = [
            'id', 'name', 'description', 'resource', 'action', 
            'user_attribute_conditions', 'resource_attribute_conditions', 'environment_conditions',
            'priority', 'effect', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserRole model (role assignments).
    """
    role = RoleSerializer(read_only=True)
    user = serializers.SerializerMethodField()
    assigned_by = serializers.SerializerMethodField()
    
    class Meta:
        model = UserRole
        fields = ['id', 'user', 'role', 'assigned_by', 'assigned_at', 'expires_at']
        read_only_fields = ['id', 'assigned_at']
    
    def get_user(self, obj):
        from users.serializers import UserSerializer
        return {
            'id': obj.user.id,
            'email': obj.user.email,
            'full_name': obj.user.get_full_name()
        }
    
    def get_assigned_by(self, obj):
        if obj.assigned_by:
            return {
                'id': obj.assigned_by.id,
                'email': obj.assigned_by.email,
                'full_name': obj.assigned_by.get_full_name()
            }
        return None