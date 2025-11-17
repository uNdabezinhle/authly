from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from apps.tenants.models import Tenant
from apps.roles.models import Permission, Role, RolePermission


class Command(BaseCommand):
    help = 'Seed authorization data (permissions and roles) for a tenant'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            required=True,
            help='Tenant schema name or domain to seed data for'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if data already exists'
        )

    def handle(self, *args, **options):
        tenant_name = options['tenant']
        force = options.get('force', False)

        # Get tenant
        try:
            if tenant_name == 'public':
                # For public schema, get the first tenant or create a dummy one
                tenant = Tenant.objects.first()
                if not tenant:
                    self.stdout.write(
                        self.style.ERROR('No tenants found. Please create a tenant first.')
                    )
                    return
            else:
                # Try to find tenant by domain name or schema name
                from apps.tenants.models import Domain
                try:
                    domain = Domain.objects.get(domain=tenant_name)
                    tenant = domain.tenant
                except Domain.DoesNotExist:
                    tenant = Tenant.objects.get(schema_name=tenant_name)
        except Tenant.DoesNotExist:
            raise CommandError(f'Tenant "{tenant_name}" not found')

        self.stdout.write(f'Seeding authorization data for tenant: {tenant.name} ({tenant.schema_name})')

        with transaction.atomic():
            # Define default permissions
            default_permissions = [
                # User management permissions
                {
                    'codename': 'users.view_profile',
                    'name': 'View User Profile',
                    'description': 'Can view user profile information'
                },
                {
                    'codename': 'users.change_profile',
                    'name': 'Change User Profile',
                    'description': 'Can modify user profile information'
                },
                {
                    'codename': 'users.change_password',
                    'name': 'Change Password',
                    'description': 'Can change user passwords'
                },
                {
                    'codename': 'users.manage_users',
                    'name': 'Manage Users',
                    'description': 'Can create, update, and deactivate users'
                },
                # API Key permissions
                {
                    'codename': 'api_keys.view_own',
                    'name': 'View Own API Keys',
                    'description': 'Can view own API keys'
                },
                {
                    'codename': 'api_keys.create_own',
                    'name': 'Create Own API Keys',
                    'description': 'Can create own API keys'
                },
                {
                    'codename': 'api_keys.delete_own',
                    'name': 'Delete Own API Keys',
                    'description': 'Can delete own API keys'
                },
                {
                    'codename': 'api_keys.manage_all',
                    'name': 'Manage All API Keys',
                    'description': 'Can manage all API keys in the tenant'
                },
                # Role management permissions
                {
                    'codename': 'roles.view_roles',
                    'name': 'View Roles',
                    'description': 'Can view roles and permissions'
                },
                {
                    'codename': 'roles.manage_roles',
                    'name': 'Manage Roles',
                    'description': 'Can create, update, and delete roles'
                },
                {
                    'codename': 'roles.assign_roles',
                    'name': 'Assign Roles',
                    'description': 'Can assign roles to users'
                },
                # Webhook permissions
                {
                    'codename': 'webhooks.view_own',
                    'name': 'View Own Webhooks',
                    'description': 'Can view own webhooks'
                },
                {
                    'codename': 'webhooks.manage_own',
                    'name': 'Manage Own Webhooks',
                    'description': 'Can create and manage own webhooks'
                },
                {
                    'codename': 'webhooks.manage_all',
                    'name': 'Manage All Webhooks',
                    'description': 'Can manage all webhooks in the tenant'
                },
                # Audit permissions
                {
                    'codename': 'audit.view_logs',
                    'name': 'View Audit Logs',
                    'description': 'Can view audit logs and activity'
                },
                {
                    'codename': 'audit.export_logs',
                    'name': 'Export Audit Logs',
                    'description': 'Can export audit logs and reports'
                },
                # Tenant management permissions
                {
                    'codename': 'tenant.manage_settings',
                    'name': 'Manage Tenant Settings',
                    'description': 'Can manage tenant configuration and settings'
                },
                {
                    'codename': 'tenant.view_analytics',
                    'name': 'View Tenant Analytics',
                    'description': 'Can view tenant usage and analytics'
                }
            ]

            # Create permissions
            created_permissions = {}
            for perm_data in default_permissions:
                permission, created = Permission.objects.get_or_create(
                    codename=perm_data['codename'],
                    tenant=tenant,
                    defaults={
                        'name': perm_data['name'],
                        'description': perm_data['description']
                    }
                )
                created_permissions[perm_data['codename']] = permission
                
                if created:
                    self.stdout.write(f'✓ Created permission: {permission.codename}')
                elif force:
                    permission.name = perm_data['name']
                    permission.description = perm_data['description']
                    permission.save()
                    self.stdout.write(f'⟳ Updated permission: {permission.codename}')
                else:
                    self.stdout.write(f'- Permission already exists: {permission.codename}')

            # Define default roles
            default_roles = [
                {
                    'name': 'admin',
                    'description': 'Full administrative access to all features',
                    'is_system': True,
                    'permissions': [
                        'users.view_profile', 'users.change_profile', 'users.change_password', 'users.manage_users',
                        'api_keys.view_own', 'api_keys.create_own', 'api_keys.delete_own', 'api_keys.manage_all',
                        'roles.view_roles', 'roles.manage_roles', 'roles.assign_roles',
                        'webhooks.view_own', 'webhooks.manage_own', 'webhooks.manage_all',
                        'audit.view_logs', 'audit.export_logs',
                        'tenant.manage_settings', 'tenant.view_analytics'
                    ]
                },
                {
                    'name': 'user',
                    'description': 'Standard user access with basic functionality',
                    'is_system': True,
                    'permissions': [
                        'users.view_profile', 'users.change_profile', 'users.change_password',
                        'api_keys.view_own', 'api_keys.create_own', 'api_keys.delete_own',
                        'webhooks.view_own', 'webhooks.manage_own'
                    ]
                },
                {
                    'name': 'viewer',
                    'description': 'Read-only access to basic features',
                    'is_system': True,
                    'permissions': [
                        'users.view_profile',
                        'api_keys.view_own',
                        'webhooks.view_own'
                    ]
                },
                {
                    'name': 'api_manager',
                    'description': 'Specialized role for managing API integrations',
                    'is_system': False,
                    'permissions': [
                        'users.view_profile', 'users.change_profile',
                        'api_keys.view_own', 'api_keys.create_own', 'api_keys.delete_own',
                        'webhooks.view_own', 'webhooks.manage_own', 'webhooks.manage_all'
                    ]
                }
            ]

            # Create roles and assign permissions
            for role_data in default_roles:
                role, created = Role.objects.get_or_create(
                    name=role_data['name'],
                    tenant=tenant,
                    defaults={
                        'description': role_data['description'],
                        'is_system': role_data['is_system']
                    }
                )
                
                if created:
                    self.stdout.write(f'✓ Created role: {role.name}')
                elif force:
                    role.description = role_data['description']
                    role.is_system = role_data['is_system']
                    role.save()
                    self.stdout.write(f'⟳ Updated role: {role.name}')
                else:
                    self.stdout.write(f'- Role already exists: {role.name}')

                # Assign permissions to role
                for perm_codename in role_data['permissions']:
                    permission = created_permissions.get(perm_codename)
                    if permission:
                        role_permission, created = RolePermission.objects.get_or_create(
                            role=role,
                            permission=permission,
                            tenant=tenant
                        )
                        if created:
                            self.stdout.write(f'  ✓ Assigned {perm_codename} to {role.name}')

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Authorization seeding completed for tenant: {tenant.name}'
            )
        )
        self.stdout.write('Created permissions: ' + str(len(default_permissions)))
        self.stdout.write('Created roles: ' + str(len(default_roles)))
        self.stdout.write('\n📖 Available roles:')
        for role in default_roles:
            self.stdout.write(f'  • {role["name"]}: {role["description"]}')