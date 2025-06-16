# sso/views.py

from datetime import timedelta
import logging

from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth import login
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend

from users.models import RefreshToken as UserRefreshToken
from .models import IdentityProvider, SSOUserMapping, SSOSession
from .serializers import (
    IdentityProviderSerializer,
    IdentityProviderDetailSerializer,
    SSOUserMappingSerializer,
    SSOSessionSerializer,
    SSOLoginInitSerializer,
    SSOLDAPLoginSerializer,
    SSOCallbackSerializer
)

logger = logging.getLogger('authly.sso')

class HasSSOManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with SSO management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with SSO management permissions
        from roles.models import UserRole
        user_roles = UserRole.objects.filter(
            user=request.user, 
            role__permissions__codename='sso:manage'
        )
        
        return user_roles.exists()

class IdentityProviderViewSet(viewsets.ModelViewSet):
    """
    ViewSet for IdentityProvider CRUD operations.
    """
    queryset = IdentityProvider.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['protocol', 'is_active']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at', 'protocol']
    ordering = ['name']
    
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return IdentityProviderDetailSerializer
        return IdentityProviderSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'enabled']:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), HasSSOManagementPermission()]
    
    @action(detail=False, methods=['get'])
    def enabled(self, request):
        """
        List all enabled identity providers for the login page.
        """
        providers = IdentityProvider.objects.filter(is_active=True)
        serializer = self.get_serializer(providers, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def mappings(self, request, pk=None):
        """
        List all user mappings for this identity provider.
        """
        provider = self.get_object()
        mappings = SSOUserMapping.objects.filter(identity_provider=provider)
        serializer = SSOUserMappingSerializer(mappings, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def sessions(self, request, pk=None):
        """
        List all active sessions for this identity provider.
        """
        provider = self.get_object()
        now = timezone.now()
        sessions = SSOSession.objects.filter(
            user_mapping__identity_provider=provider,
            expires_at__gt=now,
            is_active=True
        )
        serializer = SSOSessionSerializer(sessions, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """
        Toggle the active status of an identity provider.
        """
        provider = self.get_object()
        provider.is_active = not provider.is_active
        provider.save(update_fields=['is_active', 'updated_at'])
        
        status_str = "enabled" if provider.is_active else "disabled"
        return Response({'detail': _(f"Identity provider {provider.name} has been {status_str}.")})

class SSOUserMappingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for SSOUserMapping CRUD operations.
    """
    queryset = SSOUserMapping.objects.all()
    serializer_class = SSOUserMappingSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['identity_provider']
    search_fields = ['external_id', 'external_email', 'external_username', 'user__email']
    ordering_fields = ['created_at', 'updated_at', 'last_login']
    ordering = ['-created_at']
    
    def get_permissions(self):
        return [permissions.IsAuthenticated(), HasSSOManagementPermission()]
    
    @action(detail=True, methods=['delete'])
    def unlink(self, request, pk=None):
        """
        Unlink a user from an identity provider.
        """
        mapping = self.get_object()
        user_email = mapping.user.email
        provider_name = mapping.identity_provider.name
        
        # Delete the mapping
        mapping.delete()
        
        return Response({
            'detail': _(f"User {user_email} has been unlinked from {provider_name}.")
        })

class SSOSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for SSOSession read operations.
    """
    queryset = SSOSession.objects.all()
    serializer_class = SSOSessionSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active', 'user_mapping__identity_provider']
    search_fields = ['session_id', 'user_mapping__user__email']
    ordering_fields = ['started_at', 'expires_at']
    ordering = ['-started_at']
    
    def get_permissions(self):
        return [permissions.IsAuthenticated(), HasSSOManagementPermission()]
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """
        Revoke an SSO session.
        """
        session = self.get_object()
        
        if not session.is_active:
            return Response(
                {'detail': _("Session is already inactive.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log out the session
        session.logout()
        
        return Response({'detail': _("Session has been revoked.")})
    
    @action(detail=False, methods=['post'])
    def revoke_all(self, request):
        """
        Revoke all active sessions.
        """
        count = SSOSession.objects.filter(is_active=True).update(
            is_active=False,
            logged_out_at=timezone.now()
        )
        
        return Response({'detail': _(f"{count} sessions have been revoked.")})

class SSOLoginInitView(APIView):
    """
    View for initiating an SSO login flow.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = SSOLoginInitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        provider_id = serializer.validated_data['provider_id']
        next_url = serializer.validated_data.get('next', '/')
        
        # Get the identity provider
        try:
            provider = IdentityProvider.objects.get(id=provider_id, is_active=True)
        except IdentityProvider.DoesNotExist:
            return Response(
                {'detail': _("Identity provider not found or not active.")},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get the protocol handler
        handler = provider.protocol_handler
        if not handler:
            return Response(
                {'detail': _("Protocol handler not available.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Start the login flow
        if provider.protocol == 'ldap':
            # LDAP requires username/password form
            return Response({
                'provider': IdentityProviderSerializer(provider).data,
                'requires_credentials': True
            })
        else:
            # Other protocols redirect to the IdP
            redirect_url = handler.process_login(request)
            if not redirect_url:
                return Response(
                    {'detail': _("Failed to initiate login flow.")},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({
                'redirect_url': redirect_url
            })

class SSOLDAPLoginView(APIView):
    """
    View for LDAP/Active Directory login.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = SSOLDAPLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        provider_id = serializer.validated_data['provider_id']
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        next_url = serializer.validated_data.get('next', '/')
        
        # Get the identity provider
        try:
            provider = IdentityProvider.objects.get(id=provider_id, is_active=True, protocol='ldap')
        except IdentityProvider.DoesNotExist:
            return Response(
                {'detail': _("LDAP provider not found or not active.")},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get the protocol handler
        handler = provider.protocol_handler
        if not handler:
            return Response(
                {'detail': _("LDAP handler not available.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add credentials to the request
        request.POST = request.POST.copy()
        request.POST['username'] = username
        request.POST['password'] = password
        request.POST['next'] = next_url
        
        # Process LDAP authentication
        user, errors, redirect_to = handler.process_callback(request)
        
        if errors:
            return Response(
                {'detail': errors[0]},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not user:
            return Response(
                {'detail': _("Authentication failed.")},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate tokens for API authentication
        refresh = RefreshToken.for_user(user)
        
        # Create a refresh token record
        UserRefreshToken.objects.create(
            user=user,
            token=str(refresh),
            expires_at=timezone.now() + timedelta(days=7),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Return tokens and user info
        from users.serializers import UserSerializer
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'redirect_to': redirect_to
        })

@method_decorator(csrf_exempt, name='dispatch')
class SSOCallbackView(APIView):
    """
    View for handling SSO callback from IdP.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, *args, **kwargs):
        return self._handle_callback(request)
    
    def post(self, request, *args, **kwargs):
        return self._handle_callback(request)
    
    def _handle_callback(self, request):
        # Get the provider ID from the URL path
        provider_id = self.kwargs.get('provider_id')
        if not provider_id:
            return Response(
                {'detail': _("Provider ID is required.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the identity provider
        try:
            provider = IdentityProvider.objects.get(id=provider_id, is_active=True)
        except IdentityProvider.DoesNotExist:
            return Response(
                {'detail': _("Identity provider not found or not active.")},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get the protocol handler
        handler = provider.protocol_handler
        if not handler:
            return Response(
                {'detail': _("Protocol handler not available.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process the callback
        user, errors, redirect_to = handler.process_callback(request)
        
        if errors:
            logger.error(f"SSO callback error: {errors}")
            # Redirect to error page
            error_page = f"{provider.config.get('error_redirect_url', '/login')}?error={errors[0]}"
            return redirect(error_page)
        
        if not user:
            logger.error("SSO callback returned no user")
            # Redirect to error page
            error_page = f"{provider.config.get('error_redirect_url', '/login')}?error=Authentication failed"
            return redirect(error_page)
        
        # Log in the user
        login(request, user)
        
        # Redirect to the target URL
        if not redirect_to:
            redirect_to = provider.config.get('default_redirect_url', '/')
        
        return redirect(redirect_to)

# API version of the callback that returns tokens instead of redirecting
class SSOCallbackAPIView(APIView):
    """
    API view for handling SSO callback and returning tokens.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = SSOCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        provider_id = serializer.validated_data['provider_id']
        
        # Get the identity provider
        try:
            provider = IdentityProvider.objects.get(id=provider_id, is_active=True)
        except IdentityProvider.DoesNotExist:
            return Response(
                {'detail': _("Identity provider not found or not active.")},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get the protocol handler
        handler = provider.protocol_handler
        if not handler:
            return Response(
                {'detail': _("Protocol handler not available.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process the callback
        user, errors, redirect_to = handler.process_callback(request)
        
        if errors:
            return Response(
                {'detail': errors[0]},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not user:
            return Response(
                {'detail': _("Authentication failed.")},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate tokens for API authentication
        refresh = RefreshToken.for_user(user)
        
        # Create a refresh token record
        UserRefreshToken.objects.create(
            user=user,
            token=str(refresh),
            expires_at=timezone.now() + timedelta(days=7),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Return tokens and user info
        from users.serializers import UserSerializer
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'redirect_to': redirect_to
        })

class IdentityProviderViewSet(viewsets.ModelViewSet):
    queryset = IdentityProvider.objects.all()
    serializer_class = IdentityProviderSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = IdentityProvider.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs

    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(tenant=tenant)

class SSOUserMappingViewSet(viewsets.ModelViewSet):
    queryset = SSOUserMapping.objects.all()
    serializer_class = SSOUserMappingSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = SSOUserMapping.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs

    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(tenant=tenant)

class SSOSessionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SSOSession.objects.all()
    serializer_class = SSOSessionSerializer

    def get_queryset(self):
        tenant = getattr(self.request.user, 'tenant', None)
        qs = SSOSession.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        return qs