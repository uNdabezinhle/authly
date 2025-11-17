# apps/users/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.files.storage import default_storage

class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(default=False)
    tenant = models.ForeignKey(
        'tenants.Tenant',
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='users'
    )

    # Profile
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    bio = models.TextField(blank=True)
    preferred_name = models.CharField(max_length=100, blank=True)

    # Privacy
    PRIVACY_CHOICES = [('public', 'Public'), ('tenant', 'Tenant'), ('private', 'Private')]
    privacy_email = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='tenant')
    privacy_phone = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='private')
    privacy_name = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='public')
    privacy_avatar = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='public')
    privacy_bio = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='tenant')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

    def delete(self, *args, **kwargs):
        if self.avatar:
            default_storage.delete(self.avatar.name)
        super().delete(*args, **kwargs)

    def has_perm(self, codename, tenant=None):
        """
        Check if user has a specific permission in a tenant.
        
        Args:
            codename: Permission codename (e.g., 'users.change_profile')
            tenant: Tenant to check permission for (defaults to user's tenant)
        
        Returns:
            bool: True if user has the permission, False otherwise
        """
        # Superusers have all permissions
        if self.is_superuser:
            return True
            
        # Use user's tenant if not specified
        if tenant is None:
            tenant = self.tenant
            
        # Can't have permissions without a tenant
        if not tenant:
            return False
            
        # Import here to avoid circular imports
        from apps.roles.models import UserRole, RolePermission
        
        # Get user's roles in the specified tenant
        user_roles = UserRole.objects.filter(
            user=self,
            tenant=tenant
        ).select_related('role')
        
        # Check if any of the user's roles have the required permission
        role_permissions = RolePermission.objects.filter(
            role__in=[ur.role for ur in user_roles],
            permission__codename=codename,
            tenant=tenant
        )
        
        return role_permissions.exists()

    def has_role(self, role_name, tenant=None):
        """
        Check if user has a specific role in a tenant.
        
        Args:
            role_name: Name of the role to check for
            tenant: Tenant to check role for (defaults to user's tenant)
            
        Returns:
            bool: True if user has the role, False otherwise
        """
        # Use user's tenant if not specified
        if tenant is None:
            tenant = self.tenant
            
        # Can't have roles without a tenant
        if not tenant:
            return False
            
        # Import here to avoid circular imports
        from apps.roles.models import UserRole
        
        return UserRole.objects.filter(
            user=self,
            role__name=role_name,
            tenant=tenant
        ).exists()

    def get_permissions(self, tenant=None):
        """
        Get all permissions for the user in a tenant.
        
        Args:
            tenant: Tenant to get permissions for (defaults to user's tenant)
            
        Returns:
            list: List of permission codenames
        """
        # Use user's tenant if not specified
        if tenant is None:
            tenant = self.tenant
            
        # Can't have permissions without a tenant
        if not tenant:
            return []
            
        # Import here to avoid circular imports
        from apps.roles.models import UserRole, RolePermission
        
        # Get user's roles in the specified tenant
        user_roles = UserRole.objects.filter(
            user=self,
            tenant=tenant
        ).select_related('role')
        
        # Get all permissions through roles
        role_permissions = RolePermission.objects.filter(
            role__in=[ur.role for ur in user_roles],
            tenant=tenant
        ).select_related('permission')
        
        # Return unique permission codenames
        return list(set([
            rp.permission.codename for rp in role_permissions
        ]))

    def get_roles(self, tenant=None):
        """
        Get all roles for the user in a tenant.
        
        Args:
            tenant: Tenant to get roles for (defaults to user's tenant)
            
        Returns:
            list: List of role names
        """
        # Use user's tenant if not specified
        if tenant is None:
            tenant = self.tenant
            
        # Can't have roles without a tenant
        if not tenant:
            return []
            
        # Import here to avoid circular imports
        from apps.roles.models import UserRole
        
        user_roles = UserRole.objects.filter(
            user=self,
            tenant=tenant
        ).select_related('role')
        
        return [ur.role.name for ur in user_roles]