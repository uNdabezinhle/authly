from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from .models import Permission, Role, RolePermission, UserRole, RoleDelegation
from .serializers import (
    PermissionSerializer, RoleSerializer, RolePermissionSerializer,
    UserRoleSerializer, RoleAssignSerializer, UserPermissionsSerializer
)
from .decorators import IsTenantAdmin, IsBillingManager, IsAuditor, CanDelegateRole
from apps.users.models import User


class IsAdminPermission(permissions.BasePermission):
    """Custom permission to only allow admin users to manage roles/permissions"""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # For now, we'll check if user is superuser or has admin role
        # Later this will be replaced with proper permission checking
        if request.user.is_superuser:
            return True
            
        # Check if user has admin role in current tenant
        return UserRole.objects.filter(
            user=request.user,
            role__name='admin',
            tenant=request.tenant
        ).exists()


@extend_schema_view(
    list=extend_schema(
        summary="List permissions",
        description="List all permissions available in the current tenant"
    ),
    create=extend_schema(
        summary="Create permission",
        description="Create a new permission in the current tenant"
    ),
    retrieve=extend_schema(
        summary="Get permission details",
        description="Get details of a specific permission"
    ),
    update=extend_schema(
        summary="Update permission",
        description="Update an existing permission"
    ),
    destroy=extend_schema(
        summary="Delete permission",
        description="Delete a permission from the current tenant"
    )
)
class PermissionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing permissions"""
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get_queryset(self):
        return Permission.objects.filter(tenant=self.request.tenant)


@extend_schema_view(
    list=extend_schema(
        summary="List roles",
        description="List all roles in the current tenant"
    ),
    create=extend_schema(
        summary="Create role",
        description="Create a new role in the current tenant"
    ),
    retrieve=extend_schema(
        summary="Get role details",
        description="Get details of a specific role including its permissions"
    ),
    update=extend_schema(
        summary="Update role",
        description="Update an existing role"
    ),
    destroy=extend_schema(
        summary="Delete role",
        description="Delete a role from the current tenant (system roles cannot be deleted)"
    ),
    assign_permission=extend_schema(
        summary="Assign permission to role",
        description="Assign a permission to a role",
        request=RolePermissionSerializer
    ),
    remove_permission=extend_schema(
        summary="Remove permission from role",
        description="Remove a permission from a role"
    ),
    assign_to_user=extend_schema(
        summary="Assign role to user",
        description="Assign this role to a user",
        request=RoleAssignSerializer
    )
)
class RoleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing roles"""
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get_queryset(self):
        return Role.objects.filter(tenant=self.request.tenant)

    def destroy(self, request, *args, **kwargs):
        """Override destroy to prevent deletion of system roles"""
        role = self.get_object()
        if role.is_system:
            return Response(
                {"error": "System roles cannot be deleted."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'], url_path='permissions')
    def assign_permission(self, request, pk=None):
        """Assign a permission to this role"""
        role = self.get_object()
        serializer = RolePermissionSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                # Set the role for this assignment
                validated_data = serializer.validated_data
                validated_data['role'] = role
                role_permission = serializer.save()
                return Response(
                    RolePermissionSerializer(role_permission, context={'request': request}).data,
                    status=status.HTTP_201_CREATED
                )
            except IntegrityError:
                return Response(
                    {"error": "This permission is already assigned to this role."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'], url_path='permissions/(?P<permission_id>[^/.]+)')
    def remove_permission(self, request, pk=None, permission_id=None):
        """Remove a permission from this role"""
        role = self.get_object()
        
        try:
            role_permission = RolePermission.objects.get(
                role=role,
                permission_id=permission_id,
                tenant=request.tenant
            )
            role_permission.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except RolePermission.DoesNotExist:
            return Response(
                {"error": "Permission not found or not assigned to this role."},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post'], url_path='assign-user')
    def assign_to_user(self, request, pk=None):
        """Assign this role to a user"""
        role = self.get_object()
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response(
                {"error": "user_id is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(id=user_id, tenant=request.tenant)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found or does not belong to this tenant."},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            user_role = UserRole.objects.create(
                user=user,
                role=role,
                tenant=request.tenant,
                assigned_by=request.user
            )
            return Response(
                UserRoleSerializer(user_role, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )
        except IntegrityError:
            return Response(
                {"error": "This role is already assigned to this user."},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema_view(
    list=extend_schema(
        summary="List user role assignments",
        description="List all user-role assignments in the current tenant"
    ),
    create=extend_schema(
        summary="Assign role to user",
        description="Assign a role to a user in the current tenant"
    ),
    destroy=extend_schema(
        summary="Remove role from user",
        description="Remove a role assignment from a user"
    ),
    my_permissions=extend_schema(
        summary="Get current user permissions",
        description="Get the current user's effective permissions",
        responses={200: UserPermissionsSerializer}
    )
)
class UserRoleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing user role assignments"""
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated, IsAdminPermission]
    http_method_names = ['get', 'post', 'delete']  # Only allow GET, POST, DELETE

    def get_queryset(self):
        return UserRole.objects.filter(tenant=self.request.tenant).select_related(
            'user', 'role', 'assigned_by'
        )

    @action(detail=False, methods=['get'], url_path='me/permissions')
    def my_permissions(self, request):
        """Get current user's effective permissions"""
        user = request.user
        tenant = request.tenant

        # Get all roles for the user in this tenant
        user_roles = UserRole.objects.filter(
            user=user,
            tenant=tenant
        ).select_related('role')

        # Get all permissions through roles
        role_permissions = RolePermission.objects.filter(
            role__in=[ur.role for ur in user_roles],
            tenant=tenant
        ).select_related('permission')

        # Extract unique permission codenames
        permission_codenames = list(set([
            rp.permission.codename for rp in role_permissions
        ]))

        # Extract role names
        role_names = [ur.role.name for ur in user_roles]

        data = {
            'permissions': permission_codenames,
            'roles': role_names
        }

        serializer = UserPermissionsSerializer(data)
        return Response(serializer.data)


class DelegatedRoleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing delegated role assignments"""
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'delete']
    
    def get_queryset(self):
        # Only show assignments made by current user through delegation
        return UserRole.objects.filter(
            tenant=self.request.tenant,
            assigned_by=self.request.user,
            assignment_source='delegation'
        ).select_related('user', 'role')
    
    @action(detail=False, methods=['post'], url_path='delegate-role')
    def delegate_role(self, request):
        """Delegate a role to another user"""
        role_id = request.data.get('role_id')
        user_id = request.data.get('user_id')
        expires_in_days = request.data.get('expires_in_days', 30)
        conditions = request.data.get('conditions', {})
        
        if not role_id or not user_id:
            return Response(
                {'error': 'role_id and user_id are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            role = Role.objects.get(id=role_id, tenant=request.tenant)
            target_user = User.objects.get(id=user_id, tenant=request.tenant)
        except (Role.DoesNotExist, User.DoesNotExist):
            return Response(
                {'error': 'Role or user not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if user can delegate this role
        can_delegate, message = self.check_delegation_permission(request.user, role, target_user)
        if not can_delegate:
            return Response({'error': message}, status=status.HTTP_403_FORBIDDEN)
        
        # Check role-specific delegation rules
        role_can_delegate, role_message = role.can_delegate_to_user(request.user, target_user)
        if not role_can_delegate:
            return Response({'error': role_message}, status=status.HTTP_403_FORBIDDEN)
        
        # Create the role assignment
        try:
            expires_at = timezone.now() + timedelta(days=expires_in_days)
            
            user_role = UserRole.objects.create(
                user=target_user,
                role=role,
                tenant=request.tenant,
                assigned_by=request.user,
                assignment_source='delegation',
                expires_at=expires_at,
                conditions=conditions,
                delegation_chain=[{
                    'user_id': str(request.user.id),
                    'timestamp': timezone.now().isoformat()
                }]
            )
            
            # Log the delegation in audit
            from apps.audit.models import AuditLog
            AuditLog.create_log(
                action='role_delegated',
                user=request.user,
                details={
                    'role_id': str(role.id),
                    'role_name': role.name,
                    'target_user_id': str(target_user.id),
                    'target_user_email': target_user.email,
                    'expires_at': expires_at.isoformat()
                },
                risk_level='medium'
            )
            
            return Response(
                UserRoleSerializer(user_role, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )
            
        except IntegrityError:
            return Response(
                {'error': 'Role is already assigned to this user'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def check_delegation_permission(self, delegator, role, target_user):
        """Check if delegator can assign role to target user"""
        
        # Check if user is tenant admin (can delegate anything)
        if UserRole.objects.filter(
            user=delegator, 
            role__level='tenant_admin',
            is_active=True,
            revoked_at__isnull=True
        ).exists():
            return True, "OK"
        
        # Check if user has specific delegation permission
        delegation = RoleDelegation.objects.filter(
            delegate=delegator,
            role=role,
            is_active=True,
            revoked_at__isnull=True,
            expires_at__gt=timezone.now()
        ).first()
        
        if delegation:
            return delegation.can_assign_to_user(target_user)
        
        return False, "No delegation permission for this role"
    
    @action(detail=False, methods=['get'], url_path='my-delegations')
    def my_delegations(self, request):
        """Get delegations granted to current user"""
        delegations = RoleDelegation.objects.filter(
            delegate=request.user,
            is_active=True,
            revoked_at__isnull=True
        ).select_related('role', 'delegator')
        
        data = []
        for delegation in delegations:
            assignments_count = UserRole.objects.filter(
                role=delegation.role,
                assigned_by=request.user,
                assignment_source='delegation'
            ).count()
            
            data.append({
                'id': delegation.id,
                'role': {
                    'id': delegation.role.id,
                    'name': delegation.role.name,
                    'level': delegation.role.level
                },
                'delegator_email': delegation.delegator.email,
                'max_assignments': delegation.max_assignments,
                'current_assignments': assignments_count,
                'allowed_departments': delegation.allowed_departments,
                'expires_at': delegation.expires_at,
                'created_at': delegation.created_at
            })
        
        return Response(data)
    
    @action(detail=False, methods=['post'], url_path='revoke')
    def revoke_assignment(self, request):
        """Revoke a delegated role assignment"""
        user_role_id = request.data.get('user_role_id')
        
        if not user_role_id:
            return Response(
                {'error': 'user_role_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user_role = UserRole.objects.get(
                id=user_role_id,
                tenant=request.tenant,
                assigned_by=request.user,
                assignment_source='delegation'
            )
            
            user_role.is_active = False
            user_role.revoked_at = timezone.now()
            user_role.revoked_by = request.user
            user_role.save()
            
            # Log the revocation
            from apps.audit.models import AuditLog
            AuditLog.create_log(
                action='role_revoked',
                user=request.user,
                details={
                    'role_id': str(user_role.role.id),
                    'role_name': user_role.role.name,
                    'target_user_id': str(user_role.user.id),
                    'target_user_email': user_role.user.email
                },
                risk_level='medium'
            )
            
            return Response({'message': 'Role assignment revoked successfully'})
            
        except UserRole.DoesNotExist:
            return Response(
                {'error': 'Role assignment not found or not delegated by you'},
                status=status.HTTP_404_NOT_FOUND
            )


class AdminRoleManagementViewSet(viewsets.ViewSet):
    """Admin endpoints for managing delegations and advanced role features"""
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    @action(detail=False, methods=['post'], url_path='create-delegation')
    def create_delegation(self, request):
        """Create a delegation permission for a user"""
        delegator_id = request.data.get('delegator_id')
        delegate_id = request.data.get('delegate_id') 
        role_id = request.data.get('role_id')
        max_assignments = request.data.get('max_assignments', 10)
        allowed_departments = request.data.get('allowed_departments', [])
        expires_in_days = request.data.get('expires_in_days', 90)
        
        if not all([delegator_id, delegate_id, role_id]):
            return Response(
                {'error': 'delegator_id, delegate_id, and role_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            delegator = User.objects.get(id=delegator_id, tenant=request.tenant)
            delegate = User.objects.get(id=delegate_id, tenant=request.tenant)
            role = Role.objects.get(id=role_id, tenant=request.tenant)
        except (User.DoesNotExist, Role.DoesNotExist):
            return Response(
                {'error': 'Delegator, delegate, or role not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        expires_at = timezone.now() + timedelta(days=expires_in_days)
        
        try:
            delegation = RoleDelegation.objects.create(
                delegator=delegator,
                delegate=delegate,
                role=role,
                tenant=request.tenant,
                max_assignments=max_assignments,
                allowed_departments=allowed_departments,
                expires_at=expires_at
            )
            
            return Response({
                'id': delegation.id,
                'delegator_email': delegator.email,
                'delegate_email': delegate.email,
                'role_name': role.name,
                'max_assignments': max_assignments,
                'expires_at': expires_at
            }, status=status.HTTP_201_CREATED)
            
        except IntegrityError:
            return Response(
                {'error': 'Delegation already exists for this combination'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['get'], url_path='delegations')
    def list_delegations(self, request):
        """List all active delegations in tenant"""
        delegations = RoleDelegation.objects.filter(
            tenant=request.tenant,
            is_active=True,
            revoked_at__isnull=True
        ).select_related('delegator', 'delegate', 'role')
        
        data = []
        for delegation in delegations:
            data.append({
                'id': delegation.id,
                'delegator_email': delegation.delegator.email,
                'delegate_email': delegation.delegate.email,
                'role_name': delegation.role.name,
                'role_level': delegation.role.level,
                'max_assignments': delegation.max_assignments,
                'allowed_departments': delegation.allowed_departments,
                'expires_at': delegation.expires_at,
                'created_at': delegation.created_at
            })
        
        return Response(data)
    
    @action(detail=False, methods=['post'], url_path='revoke-delegation')
    def revoke_delegation(self, request):
        """Revoke a delegation permission"""
        delegation_id = request.data.get('delegation_id')
        
        if not delegation_id:
            return Response(
                {'error': 'delegation_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            delegation = RoleDelegation.objects.get(
                id=delegation_id,
                tenant=request.tenant
            )
            
            delegation.is_active = False
            delegation.revoked_at = timezone.now()
            delegation.revoked_by = request.user
            delegation.save()
            
            # Also revoke all assignments made through this delegation
            UserRole.objects.filter(
                role=delegation.role,
                assigned_by=delegation.delegate,
                assignment_source='delegation'
            ).update(
                is_active=False,
                revoked_at=timezone.now(),
                revoked_by=request.user
            )
            
            return Response({'message': 'Delegation revoked successfully'})
            
        except RoleDelegation.DoesNotExist:
            return Response(
                {'error': 'Delegation not found'},
                status=status.HTTP_404_NOT_FOUND
            )


