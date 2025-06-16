# users/views/user_views.py

from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404

from users.models import User,  TwoFactorDevice, RefreshToken
from users.serializers import UserSerializer, UserCreateSerializer, UserUpdateSerializer, TwoFactorDeviceSerializer, RefreshTokenSerializer
from roles.models import Role, UserRole

from rest_framework import viewsets


class IsAdminOrSelf(permissions.BasePermission):
    """
    Permission to only allow admins or the user themselves to access/modify their data.
    """
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Allow users to access/modify their own data
        return obj.id == request.user.id

class HasUserManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with specific user management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with user management permissions
        user_roles = UserRole.objects.filter(user=request.user, role__permissions__codename='user:manage')
        
        # Check if there are any active roles
        return user_roles.exists()

class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for User CRUD operations.
    """
    queryset = User.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active', 'email_verified', 'phone_verified', 'two_factor_enabled']
    search_fields = ['email', 'username', 'first_name', 'last_name', 'phone_number']
    ordering_fields = ['date_joined', 'last_login', 'email', 'username', 'first_name', 'last_name']
    ordering = ['-date_joined']
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer
    
    def get_permissions(self):
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsAdminOrSelf()]
        elif self.action == 'list' or self.action == 'create' or self.action == 'destroy':
            return [permissions.IsAuthenticated(), HasUserManagementPermission()]
        elif self.action == 'me':
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated()]
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Endpoint to get the currently authenticated user's information.
        """
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """
        Endpoint to activate a user account.
        """
        user = self.get_object()
        user.is_active = True
        user.save(update_fields=['is_active'])
        return Response({'detail': _('User account has been activated.')})
    
    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        """
        Endpoint to deactivate a user account.
        """
        user = self.get_object()
        
        # Cannot deactivate yourself
        if user.id == request.user.id:
            return Response(
                {'detail': _('You cannot deactivate your own account.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Cannot deactivate superusers unless you are a superuser
        if user.is_superuser and not request.user.is_superuser:
            return Response(
                {'detail': _('You cannot deactivate a superuser account.')},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user.is_active = False
        user.save(update_fields=['is_active'])
        return Response({'detail': _('User account has been deactivated.')})
    
    @action(detail=True, methods=['post'])
    def unlock(self, request, pk=None):
        """
        Endpoint to unlock a locked user account.
        """
        user = self.get_object()
        if user.is_locked():
            user.unlock_account()
            return Response({'detail': _('User account has been unlocked.')})
        return Response(
            {'detail': _('User account is not locked.')},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=True, methods=['get'])
    def roles(self, request, pk=None):
        """
        Endpoint to get all roles assigned to a user.
        """
        user = self.get_object()
        roles = Role.objects.filter(user_roles__user=user)
        
        # Custom serializer for roles data
        from roles.serializers import RoleSerializer
        serializer = RoleSerializer(roles, many=True)
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def add_role(self, request, pk=None):
        """
        Endpoint to assign a role to a user.
        """
        user = self.get_object()
        
        # Validate input
        role_id = request.data.get('role_id')
        if not role_id:
            return Response(
                {'detail': _('Role ID is required.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the role
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response(
                {'detail': _('Role not found.')},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if the role is already assigned
        if UserRole.objects.filter(user=user, role=role).exists():
            return Response(
                {'detail': _('Role is already assigned to this user.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the user-role relationship
        expiry = request.data.get('expires_at')  # Optional expiry date
        user_role = UserRole.objects.create(
            user=user,
            role=role,
            assigned_by=request.user,
            expires_at=expiry
        )
        
        return Response({'detail': _('Role has been assigned to the user.')}, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def remove_role(self, request, pk=None):
        """
        Endpoint to remove a role from a user.
        """
        user = self.get_object()
        
        # Validate input
        role_id = request.data.get('role_id')
        if not role_id:
            return Response(
                {'detail': _('Role ID is required.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the role
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response(
                {'detail': _('Role not found.')},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if the role is assigned
        try:
            user_role = UserRole.objects.get(user=user, role=role)
            user_role.delete()
            return Response({'detail': _('Role has been removed from the user.')})
        except UserRole.DoesNotExist:
            return Response(
                {'detail': _('Role is not assigned to this user.')},
                status=status.HTTP_400_BAD_REQUEST
            )

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = User.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer

    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(tenant=tenant)

class TwoFactorDeviceViewSet(viewsets.ModelViewSet):
    queryset = TwoFactorDevice.objects.all()
    serializer_class = TwoFactorDeviceSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = TwoFactorDevice.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs

    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(tenant=tenant)

class RefreshTokenViewSet(viewsets.ModelViewSet):
    queryset = RefreshToken.objects.all()
    serializer_class = RefreshTokenSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = RefreshToken.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs

    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(tenant=tenant)