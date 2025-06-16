# api_keys/views.py

from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import APIKey, APIKeyUsage
from .serializers import APIKeySerializer, APIKeyCreateSerializer, APIKeyDetailSerializer, APIKeyUsageSerializer

class HasAPIKeyManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with API key management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with API key management permissions
        from roles.models import UserRole
        user_roles = UserRole.objects.filter(
            user=request.user, 
            role__permissions__codename='api_key:manage'
        )
        
        return user_roles.exists()

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to only allow owners of an API key or admins to view/edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Allow users to access/modify their own API keys
        return obj.user.id == request.user.id

class APIKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for API Key CRUD operations.
    """
    queryset = APIKey.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active']
    search_fields = ['name', 'description', 'prefix']
    ordering_fields = ['name', 'created_at', 'last_used_at', 'expires_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        # Regular users can only see their own API keys
        if not self.request.user.is_staff:
            return APIKey.objects.filter(user=self.request.user)
        # Admins can see all API keys
        return APIKey.objects.all()
    
    def get_serializer_class(self):
        if self.action == 'create':
            return APIKeyCreateSerializer
        elif self.action == 'retrieve' or self.action == 'me':
            return APIKeyDetailSerializer
        return APIKeySerializer
    
    def get_permissions(self):
        if self.action in ['me', 'list', 'retrieve', 'create']:
            return [permissions.IsAuthenticated()]
        elif self.action in ['update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsOwnerOrAdmin()]
        return [permissions.IsAuthenticated(), HasAPIKeyManagementPermission()]
    
    def perform_create(self, serializer):
        # Set the user to the current user
        serializer.save(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get all API keys for the currently authenticated user.
        """
        api_keys = APIKey.objects.filter(user=request.user)
        serializer = self.get_serializer(api_keys, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """
        Revoke (deactivate) an API key.
        """
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save(update_fields=['is_active'])
        return Response({'detail': _('API key has been revoked.')})
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """
        Activate a previously revoked API key.
        """
        api_key = self.get_object()
        api_key.is_active = True
        api_key.save(update_fields=['is_active'])
        return Response({'detail': _('API key has been activated.')})
    
    @action(detail=True, methods=['get'])
    def usage(self, request, pk=None):
        """
        Get the usage logs for an API key.
        """
        api_key = self.get_object()
        
        # Get optional date filters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        # Base query
        usage_logs = APIKeyUsage.objects.filter(api_key=api_key)
        
        # Apply date filters if provided
        if start_date:
            usage_logs = usage_logs.filter(timestamp__gte=start_date)
        if end_date:
            usage_logs = usage_logs.filter(timestamp__lte=end_date)
        
        # Get stats
        total_requests = usage_logs.count()
        success_requests = usage_logs.filter(response_status__lt=400).count()
        failed_requests = total_requests - success_requests
        
        # Get recent usage logs
        recent_logs = usage_logs.order_by('-timestamp')[:100]  # Limit to 100 most recent logs
        serializer = APIKeyUsageSerializer(recent_logs, many=True)
        
        return Response({
            'total_requests': total_requests,
            'success_requests': success_requests,
            'failed_requests': failed_requests,
            'recent_logs': serializer.data
        })