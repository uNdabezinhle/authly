from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, extend_schema_view
from apps.roles.permissions import permission_required, IsOwnerOrAdmin
from .models import APIKey
from .serializers import (
    APIKeySerializer, 
    APIKeyCreateSerializer, 
    APIKeyDetailSerializer
)


@extend_schema_view(
    list=extend_schema(
        summary="List API keys",
        description="Get a list of API keys for the authenticated user",
        responses={200: APIKeySerializer(many=True)}
    ),
    create=extend_schema(
        summary="Create API key",
        description="Create a new API key for the authenticated user",
        request=APIKeyCreateSerializer,
        responses={201: APIKeyDetailSerializer}
    ),
    destroy=extend_schema(
        summary="Delete API key",
        description="Delete (revoke) an API key",
        responses={204: None}
    )
)
class APIKeyViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    http_method_names = ['get', 'post', 'delete']  # Only allow list, create, delete

    def get_queryset(self):
        # Admin users can see all API keys in tenant, others only their own
        if self.request.user.has_role('admin', self.request.tenant):
            return APIKey.objects.filter(tenant=self.request.tenant).order_by('-created_at')
        else:
            return APIKey.objects.filter(
                user=self.request.user,
                tenant=self.request.tenant
            ).order_by('-created_at')

    def get_serializer_class(self):
        if self.action == 'create':
            return APIKeyCreateSerializer
        elif self.action == 'retrieve':
            return APIKeyDetailSerializer
        return APIKeySerializer

    @permission_required('api_keys.view_own')
    def list(self, request):
        """List API keys"""
        return super().list(request)

    @permission_required('api_keys.create_own')
    def create(self, request):
        """Create a new API key"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        api_key = serializer.save()
        
        # Return the key with raw key (shown only once)
        response_serializer = APIKeyDetailSerializer(api_key)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    @permission_required('api_keys.delete_own')
    def destroy(self, request, pk=None):
        """Delete (revoke) an API key"""
        try:
            api_key = self.get_queryset().get(pk=pk)
            # Additional check for ownership unless admin
            if not request.user.has_role('admin', request.tenant) and api_key.user != request.user:
                return Response(
                    {"error": "You can only delete your own API keys"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            api_key.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except APIKey.DoesNotExist:
            return Response(
                {"error": "API key not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )


