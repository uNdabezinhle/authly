# roles/views.py

from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.db.models import Q

from .models import Role, Permission, Group, UserRole, ABACRule
from .serializers import (
    RoleSerializer, 
    RoleDetailSerializer, 
    RoleCreateSerializer,
    RolePermissionAssignSerializer,
    PermissionSerializer,
    GroupSerializer,
    GroupDetailSerializer,
    ABACRuleSerializer,
    UserRoleSerializer
)

class HasRoleManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with role management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with role management permissions
        user_roles = UserRole.objects.filter(
            user=request.user, 
            role__permissions__codename='role:manage'
        )
        
        return user_roles.exists()

class HasPermissionManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with permission management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with permission management permissions
        user_roles = UserRole.objects.filter(
            user=request.user, 
            role__permissions__codename='permission:manage'
        )
        
        return user_roles.exists()

class RoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Role CRUD operations.
    """
    queryset = Role.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_system_role']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return RoleDetailSerializer
        elif self.action == 'create':
            return RoleCreateSerializer
        return RoleSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), HasRoleManagementPermission()]
    
    def perform_destroy(self, instance):
        # Prevent deletion of system roles
        if instance.is_system_role:
            raise permissions.PermissionDenied(_("System roles cannot be deleted."))
        super().perform_destroy(instance)
    
    @action(detail=True, methods=['get'])
    def permissions(self, request, pk=None):
        """
        Get all permissions assigned to a role.
        """
        role = self.get_object()
        permissions_list = role.permissions.all()
        serializer = PermissionSerializer(permissions_list, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def all_permissions(self, request, pk=None):
        """
        Get all permissions for this role, including those inherited from parent roles.
        """
        role = self.get_object()
        permissions_list = role.get_all_permissions()
        serializer = PermissionSerializer(permissions_list, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def add_permissions(self, request, pk=None):
        """
        Add permissions to a role.
        """
        role = self.get_object()
        serializer = RolePermissionAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        permission_ids = serializer.validated_data['permission_ids']
        permissions_to_add = Permission.objects.filter(id__in=permission_ids)
        
        # Check if all permissions exist
        if permissions_to_add.count() != len(permission_ids):
            return Response(
                {'detail': _('One or more permissions do not exist.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add permissions to role
        role.permissions.add(*permissions_to_add)
        
        return Response({'detail': _('Permissions have been added to the role.')})
    
    @action(detail=True, methods=['post'])
    def remove_permissions(self, request, pk=None):
        """
        Remove permissions from a role.
        """
        role = self.get_object()
        serializer = RolePermissionAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        permission_ids = serializer.validated_data['permission_ids']
        permissions_to_remove = Permission.objects.filter(id__in=permission_ids)
        
        # Remove permissions from role
        role.permissions.remove(*permissions_to_remove)
        
        return Response({'detail': _('Permissions have been removed from the role.')})
    
    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        """
        Get all users assigned to this role.
        """
        role = self.get_object()
        user_roles = UserRole.objects.filter(role=role)
        serializer = UserRoleSerializer(user_roles, many=True)
        return Response(serializer.data)

class PermissionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Permission CRUD operations.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['resource', 'action']
    search_fields = ['name', 'description', 'codename', 'resource', 'action']
    ordering_fields = ['name', 'resource', 'action', 'created_at']
    ordering = ['resource', 'action']
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), HasPermissionManagementPermission()]
    
    @action(detail=True, methods=['get'])
    def roles(self, request, pk=None):
        """
        Get all roles that have this permission.
        """
        permission = self.get_object()
        roles = permission.roles.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

class GroupViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Group CRUD operations.
    """
    queryset = Group.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return GroupDetailSerializer
        return GroupSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), HasRoleManagementPermission()]
    
    @action(detail=True, methods=['post'])
    def add_users(self, request, pk=None):
        """
        Add users to a group.
        """
        group = self.get_object()
        user_ids = request.data.get('user_ids', [])
        
        if not user_ids:
            return Response(
                {'detail': _('No user IDs provided.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users_to_add = User.objects.filter(id__in=user_ids)
        
        # Check if all users exist
        if users_to_add.count() != len(user_ids):
            return Response(
                {'detail': _('One or more users do not exist.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add users to group
        group.users.add(*users_to_add)
        
        return Response({'detail': _('Users have been added to the group.')})
    
    @action(detail=True, methods=['post'])
    def remove_users(self, request, pk=None):
        """
        Remove users from a group.
        """
        group = self.get_object()
        user_ids = request.data.get('user_ids', [])
        
        if not user_ids:
            return Response(
                {'detail': _('No user IDs provided.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users_to_remove = User.objects.filter(id__in=user_ids)
        
        # Remove users from group
        group.users.remove(*users_to_remove)
        
        return Response({'detail': _('Users have been removed from the group.')})
    
    @action(detail=True, methods=['post'])
    def add_roles(self, request, pk=None):
        """
        Add roles to a group.
        """
        group = self.get_object()
        role_ids = request.data.get('role_ids', [])
        
        if not role_ids:
            return Response(
                {'detail': _('No role IDs provided.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        roles_to_add = Role.objects.filter(id__in=role_ids)
        
        # Check if all roles exist
        if roles_to_add.count() != len(role_ids):
            return Response(
                {'detail': _('One or more roles do not exist.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add roles to group
        group.roles.add(*roles_to_add)
        
        return Response({'detail': _('Roles have been added to the group.')})
    
    @action(detail=True, methods=['post'])
    def remove_roles(self, request, pk=None):
        """
        Remove roles from a group.
        """
        group = self.get_object()
        role_ids = request.data.get('role_ids', [])
        
        if not role_ids:
            return Response(
                {'detail': _('No role IDs provided.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        roles_to_remove = Role.objects.filter(id__in=role_ids)
        
        # Remove roles from group
        group.roles.remove(*roles_to_remove)
        
        return Response({'detail': _('Roles have been removed from the group.')})

class ABACRuleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ABAC Rule CRUD operations.
    """
    queryset = ABACRule.objects.all()
    serializer_class = ABACRuleSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['resource', 'action', 'effect', 'is_active']
    search_fields = ['name', 'description', 'resource', 'action']
    ordering_fields = ['name', 'priority', 'resource', 'action', 'created_at']
    ordering = ['priority']
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), HasPermissionManagementPermission()]