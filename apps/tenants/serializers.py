from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.text import slugify
from django.db import transaction
from .models import Tenant, Domain

User = get_user_model()

class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ['id', 'domain', 'is_primary', 'created_on']
        read_only_fields = ['id', 'created_on']

class TenantSerializer(serializers.ModelSerializer):
    domains = DomainSerializer(many=True, read_only=True)

    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'slug', 'description', 'is_active', 
            'created_on', 'updated_on', 'plan', 'max_users',
            'contact_email', 'contact_phone', 'domains'
        ]
        read_only_fields = ['id', 'slug', 'created_on', 'updated_on']

class TenantCreationSerializer(serializers.Serializer):
    """Serializer for creating a complete tenant with admin user and domain"""
    
    # Tenant info
    name = serializers.CharField(max_length=100, help_text="Organization name")
    description = serializers.CharField(required=False, allow_blank=True, help_text="Optional description")
    domain = serializers.CharField(max_length=253, help_text="Domain name (e.g., 'company.authly.com')")
    contact_email = serializers.EmailField(required=False, allow_blank=True)
    contact_phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    plan = serializers.CharField(max_length=50, default='free')
    
    # Admin user info
    admin_email = serializers.EmailField(help_text="Admin user email")
    admin_password = serializers.CharField(min_length=8, write_only=True, help_text="Admin user password")
    admin_first_name = serializers.CharField(max_length=150, help_text="Admin first name")
    admin_last_name = serializers.CharField(max_length=150, help_text="Admin last name")

    def validate_domain(self, value):
        """Validate domain is unique and valid format"""
        if Domain.objects.filter(domain=value).exists():
            raise serializers.ValidationError("Domain already exists")
        return value.lower()

    def validate_admin_email(self, value):
        """Validate admin email is unique across all tenants"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value.lower()

    def create(self, validated_data):
        """Create tenant, domain, admin user, and default roles/permissions"""
        with transaction.atomic():
            # Extract admin user data
            admin_data = {
                'email': validated_data.pop('admin_email'),
                'password': validated_data.pop('admin_password'),
                'first_name': validated_data.pop('admin_first_name'),
                'last_name': validated_data.pop('admin_last_name'),
            }
            
            # Extract domain
            domain_name = validated_data.pop('domain')
            
            # Generate unique slug
            base_slug = slugify(validated_data['name'])
            slug = base_slug
            counter = 1
            while Tenant.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            # Create tenant
            tenant = Tenant.objects.create(slug=slug, **validated_data)
            
            # Create domain
            domain = Domain.objects.create(
                domain=domain_name,
                tenant=tenant,
                is_primary=True
            )
            
            # Switch to tenant schema for user creation
            from django_tenants.utils import schema_context
            with schema_context(tenant.schema_name):
                # Create admin user
                admin_user = User.objects.create_user(
                    username=admin_data['email'],
                    email=admin_data['email'],
                    password=admin_data['password'],
                    first_name=admin_data['first_name'],
                    last_name=admin_data['last_name'],
                    tenant=tenant,
                    is_active=True,
                    email_verified=True,  # Auto-verify for tenant admin
                )
                
                # Create default roles and permissions
                self._create_default_roles_and_permissions(tenant, admin_user)
                
            return {
                'tenant': tenant,
                'domain': domain,
                'admin_user': admin_user
            }

    def _create_default_roles_and_permissions(self, tenant, admin_user):
        """Create default roles and permissions for the tenant"""
        from apps.roles.models import Role, Permission, RolePermission, UserRole
        from django_tenants.utils import schema_context
        
        with schema_context(tenant.schema_name):
            # Default permissions
            default_permissions = [
                ('system.admin', 'System Administrator', 'Full system access'),
                ('users.view_all', 'View All Users', 'Can view all user profiles'),
                ('users.manage_all', 'Manage All Users', 'Can create, update, delete users'),
                ('users.view_own', 'View Own Profile', 'Can view own profile'),
                ('users.change_own', 'Change Own Profile', 'Can update own profile'),
                ('roles.view_all', 'View All Roles', 'Can view all roles'),
                ('roles.manage_all', 'Manage All Roles', 'Can create, update, delete roles'),
                ('api_keys.view_own', 'View Own API Keys', 'Can view own API keys'),
                ('api_keys.manage_own', 'Manage Own API Keys', 'Can create, update, delete own API keys'),
                ('webhooks.view_all', 'View All Webhooks', 'Can view webhook configurations'),
                ('webhooks.manage_all', 'Manage All Webhooks', 'Can create, update, delete webhooks'),
                ('audit.view_all', 'View Audit Logs', 'Can access audit logs'),
            ]
            
            permissions = {}
            for codename, name, description in default_permissions:
                permission = Permission.objects.create(
                    codename=codename,
                    name=name,
                    description=description,
                    tenant=tenant
                )
                permissions[codename] = permission
            
            # Create admin role with all permissions
            admin_role = Role.objects.create(
                name='admin',
                description='System Administrator with full access',
                is_system=True,
                tenant=tenant
            )
            
            # Assign all permissions to admin role
            for permission in permissions.values():
                RolePermission.objects.create(
                    role=admin_role,
                    permission=permission,
                    tenant=tenant
                )
            
            # Create user role with basic permissions
            user_role = Role.objects.create(
                name='user',
                description='Standard user with basic access',
                is_system=True,
                tenant=tenant
            )
            
            # Basic user permissions
            basic_permissions = ['users.view_own', 'users.change_own', 'api_keys.view_own', 'api_keys.manage_own']
            for codename in basic_permissions:
                if codename in permissions:
                    RolePermission.objects.create(
                        role=user_role,
                        permission=permissions[codename],
                        tenant=tenant
                    )
            
            # Assign admin role to admin user
            UserRole.objects.create(
                user=admin_user,
                role=admin_role,
                tenant=tenant
            )

class TenantCreationResponseSerializer(serializers.Serializer):
    """Response serializer for tenant creation"""
    tenant = TenantSerializer(read_only=True)
    domain = DomainSerializer(read_only=True)
    admin_token = serializers.CharField(read_only=True)
    admin_refresh_token = serializers.CharField(read_only=True)