from rest_framework import serializers
from .models import Permission, Role, RolePermission, UserRole

class PermissionSerializer(serializers.ModelSerializer):
    """Serializer for Permission model"""
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        # Automatically set tenant from request context
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)

class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Role model with nested permissions"""
    permissions = PermissionSerializer(source='role_permissions.permission', many=True, read_only=True)
    permission_count = serializers.SerializerMethodField()
    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = [
            'id', 'name', 'description', 'is_system', 
            'permissions', 'permission_count', 'user_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_permission_count(self, obj):
        return obj.role_permissions.count()

    def get_user_count(self, obj):
        return obj.user_roles.count()

    def create(self, validated_data):
        # Automatically set tenant from request context
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)

    def validate_name(self, value):
        """Ensure role name is unique within tenant"""
        tenant = self.context['request'].tenant
        queryset = Role.objects.filter(name=value, tenant=tenant)
        
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
            
        if queryset.exists():
            raise serializers.ValidationError(f"Role with name '{value}' already exists in this tenant.")
        return value

class RolePermissionSerializer(serializers.ModelSerializer):
    """Serializer for assigning permissions to roles"""
    permission_details = PermissionSerializer(source='permission', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    permission_codename = serializers.CharField(source='permission.codename', read_only=True)

    class Meta:
        model = RolePermission
        fields = [
            'id', 'role', 'permission', 'permission_details', 
            'role_name', 'permission_codename', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        # Automatically set tenant from request context
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)

    def validate(self, data):
        """Ensure role and permission belong to the same tenant"""
        tenant = self.context['request'].tenant
        role = data.get('role')
        permission = data.get('permission')

        if role and role.tenant != tenant:
            raise serializers.ValidationError("Role does not belong to the current tenant.")
        
        if permission and permission.tenant != tenant:
            raise serializers.ValidationError("Permission does not belong to the current tenant.")

        return data

class UserRoleSerializer(serializers.ModelSerializer):
    """Serializer for assigning roles to users"""
    role_details = RoleSerializer(source='role', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    assigned_by_email = serializers.CharField(source='assigned_by.email', read_only=True)

    class Meta:
        model = UserRole
        fields = [
            'id', 'user', 'role', 'role_details', 
            'user_email', 'role_name', 'assigned_by', 'assigned_by_email',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        # Automatically set tenant and assigned_by from request context
        request = self.context['request']
        validated_data['tenant'] = request.tenant
        validated_data['assigned_by'] = request.user
        return super().create(validated_data)

    def validate(self, data):
        """Ensure user and role belong to the same tenant"""
        tenant = self.context['request'].tenant
        user = data.get('user')
        role = data.get('role')

        if user and user.tenant != tenant:
            raise serializers.ValidationError("User does not belong to the current tenant.")
        
        if role and role.tenant != tenant:
            raise serializers.ValidationError("Role does not belong to the current tenant.")

        return data

class RoleAssignSerializer(serializers.Serializer):
    """Simplified serializer for assigning role to user via POST"""
    role_id = serializers.UUIDField()

    def validate_role_id(self, value):
        """Ensure role exists and belongs to current tenant"""
        tenant = self.context['request'].tenant
        try:
            role = Role.objects.get(id=value, tenant=tenant)
        except Role.DoesNotExist:
            raise serializers.ValidationError("Role not found or does not belong to this tenant.")
        return value

class UserPermissionsSerializer(serializers.Serializer):
    """Serializer for listing user's effective permissions"""
    permissions = serializers.ListField(
        child=serializers.CharField(),
        read_only=True
    )
    roles = serializers.ListField(
        child=serializers.CharField(),
        read_only=True
    )
