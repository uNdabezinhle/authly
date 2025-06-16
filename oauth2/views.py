# oauth2/views.py

import jwt
import uuid
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseRedirect, JsonResponse
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.db import transaction

from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend

from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
from .serializers import (
    OAuth2ClientSerializer,
    OAuth2ClientCreateSerializer,
    OAuth2ClientDetailSerializer,
    OAuth2AuthorizeSerializer,
    OAuth2TokenExchangeSerializer,
    OAuth2TokenSerializer,
    UserInfoSerializer
)

User = get_user_model()

class HasOAuth2ManagementPermission(permissions.BasePermission):
    """
    Permission to only allow users with OAuth2 management permissions.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Check if the user has any roles with OAuth2 management permissions
        from roles.models import UserRole
        user_roles = UserRole.objects.filter(
            user=request.user, 
            role__permissions__codename='oauth2:manage'
        )
        
        return user_roles.exists()

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to only allow owners of an OAuth2 client or admins to view/edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff:
            return True
        
        # Allow users to access/modify their own clients
        return obj.user.id == request.user.id

class OAuth2ClientViewSet(viewsets.ModelViewSet):
    """
    ViewSet for OAuth2Client CRUD operations.
    """
    queryset = OAuth2Client.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['client_type', 'is_active']
    search_fields = ['name', 'description', 'client_id']
    ordering_fields = ['name', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        # Only show clients for the current user's tenant
        tenant = getattr(self.request.user, 'tenant', None)
        qs = OAuth2Client.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        if not self.request.user.is_staff:
            qs = qs.filter(user=self.request.user)
        return qs
    
    def get_serializer_class(self):
        if self.action == 'create':
            return OAuth2ClientCreateSerializer
        elif self.action == 'retrieve' or self.action == 'me':
            return OAuth2ClientDetailSerializer
        return OAuth2ClientSerializer
    
    def get_permissions(self):
        if self.action in ['me', 'list', 'retrieve', 'create']:
            return [permissions.IsAuthenticated()]
        elif self.action in ['update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsOwnerOrAdmin()]
        return [permissions.IsAuthenticated(), HasOAuth2ManagementPermission()]
    
    def perform_create(self, serializer):
        tenant = getattr(self.request.user, 'tenant', None)
        serializer.save(user=self.request.user, tenant=tenant)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get all OAuth2 clients for the currently authenticated user.
        """
        clients = OAuth2Client.objects.filter(user=request.user)
        serializer = self.get_serializer(clients, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def regenerate_secret(self, request, pk=None):
        """
        Regenerate the client secret for a confidential client.
        """
        client = self.get_object()
        
        if client.client_type != 'confidential':
            return Response(
                {'detail': _('Only confidential clients have client secrets.')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate new secret and save
        client.client_secret = None  # Will trigger generation of a new secret on save
        client.save()
        
        return Response({
            'detail': _('Client secret has been regenerated.'),
            'client_secret': client.client_secret
        })
    
    @action(detail=True, methods=['post'])
    def revoke_tokens(self, request, pk=None):
        """
        Revoke all tokens for this client.
        """
        client = self.get_object()
        
        count = OAuth2Token.objects.filter(
            client=client, 
            revoked_at__isnull=True
        ).update(revoked_at=timezone.now())
        
        return Response({
            'detail': _('All tokens have been revoked.'),
            'count': count
        })

# Authentication views
class AuthorizeView(APIView):
    """
    OAuth2 authorize endpoint.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Handle the initial authorization request.
        """
        serializer = OAuth2AuthorizeSerializer(data=request.query_params)
        
        if not serializer.is_valid():
            return self._error_response(serializer.errors)
        
        # Store validated parameters
        params = serializer.validated_data
        client = params['client']
        response_type = params['response_type']
        redirect_uri = params['redirect_uri']
        scope = params.get('scope', '')
        state = params.get('state', '')
        code_challenge = params.get('code_challenge', '')
        code_challenge_method = params.get('code_challenge_method', '')
        
        # Render consent screen
        return render(request, 'oauth2/authorize.html', {
            'client': client,
            'scopes': scope.split() if scope else [],
            'params': request.query_params,
        })
    
    def post(self, request):
        """
        Handle the user's authorization decision.
        """
        serializer = OAuth2AuthorizeSerializer(data=request.POST)
        
        if not serializer.is_valid():
            return self._error_response(serializer.errors)
        
        # Store validated parameters
        params = serializer.validated_data
        client = params['client']
        response_type = params['response_type']
        redirect_uri = params['redirect_uri']
        scope = params.get('scope', '')
        state = params.get('state', '')
        code_challenge = params.get('code_challenge', '')
        code_challenge_method = params.get('code_challenge_method', '')
        
        # Check user's consent
        if request.POST.get('consent') != 'yes':
            return self._denied_redirect(redirect_uri, state)
        
        # Log authorization
        from audit.models import AuditLog
        AuditLog.objects.create(
            category='oauth2',
            event_type='oauth2_authorization_granted',
            user=request.user,
            details={
                'client_id': client.client_id,
                'client_name': client.name,
                'scope': scope,
                'response_type': response_type
            }
        )
        
        # Process based on response_type
        if response_type == 'code':
            # Authorization Code Flow
            with transaction.atomic():
                # Create authorization code
                auth_code = OAuth2AuthorizationCode.objects.create(
                    client=client,
                    user=request.user,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    expires_at=timezone.now() + timezone.timedelta(minutes=10)
                )
                
                # Redirect to callback URL with code
                redirect_params = f"code={auth_code.code}"
                if state:
                    redirect_params += f"&state={state}"
                
                return HttpResponseRedirect(f"{redirect_uri}?{redirect_params}")
                
        elif response_type == 'token':
            # Implicit Flow
            with transaction.atomic():
                # Create access token
                token = OAuth2Token.objects.create(
                    client=client,
                    user=request.user,
                    scope=scope,
                    access_token_expires_at=timezone.now() + timezone.timedelta(
                        seconds=client.access_token_lifetime
                    ),
                    client_ip=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Redirect to callback URL with token
                fragment = f"access_token={token.access_token}&token_type=bearer"
                fragment += f"&expires_in={client.access_token_lifetime}"
                fragment += f"&scope={scope}"
                if state:
                    fragment += f"&state={state}"
                
                return HttpResponseRedirect(f"{redirect_uri}#{fragment}")
    
    def _error_response(self, errors):
        """
        Handle authorization errors.
        """
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _denied_redirect(self, redirect_uri, state):
        """
        Redirect with access_denied error.
        """
        error_params = "error=access_denied&error_description=The+user+denied+the+request"
        if state:
            error_params += f"&state={state}"
        
        return HttpResponseRedirect(f"{redirect_uri}?{error_params}")

@method_decorator(csrf_exempt, name='dispatch')
class TokenView(APIView):
    """
    OAuth2 token endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """
        Handle token requests.
        """
        serializer = OAuth2TokenExchangeSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'invalid_request', 'error_description': str(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store validated parameters
        params = serializer.validated_data
        client = params['client']
        grant_type = params['grant_type']
        
        # Process based on grant_type
        if grant_type == 'authorization_code':
            return self._process_authorization_code(request, params)
        elif grant_type == 'refresh_token':
            return self._process_refresh_token(request, params)
        
        return Response(
            {'error': 'unsupported_grant_type'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def _process_authorization_code(self, request, params):
        """
        Process authorization code grant.
        """
        client = params['client']
        auth_code = params['auth_code']
        
        with transaction.atomic():
            # Mark code as used
            auth_code.use()
            
            # Create tokens
            token = OAuth2Token.objects.create(
                client=client,
                user=auth_code.user,
                scope=auth_code.scope,
                access_token_expires_at=timezone.now() + timezone.timedelta(
                    seconds=client.access_token_lifetime
                ),
                refresh_token_expires_at=timezone.now() + timezone.timedelta(
                    seconds=client.refresh_token_lifetime
                ) if 'refresh_token' in client.allowed_grant_types else None,
                client_ip=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log token issuance
            from audit.models import AuditLog
            AuditLog.objects.create(
                category='oauth2',
                event_type='oauth2_token_issued',
                user=auth_code.user,
                details={
                    'client_id': client.client_id,
                    'client_name': client.name,
                    'grant_type': 'authorization_code',
                    'scope': auth_code.scope
                }
            )
            
            # Prepare response
            response_data = {
                'access_token': token.access_token,
                'token_type': 'bearer',
                'expires_in': client.access_token_lifetime,
            }
            
            if token.refresh_token:
                response_data['refresh_token'] = token.refresh_token
            
            if auth_code.scope:
                response_data['scope'] = auth_code.scope
            
            return Response(response_data)
    
    def _process_refresh_token(self, request, params):
        """
        Process refresh token grant.
        """
        client = params['client']
        token = params['token']
        scope = params.get('scope', token.scope)
        
        # Validate scope (can't escalate privileges)
        if scope:
            original_scopes = set(token.scope.split() if token.scope else [])
            requested_scopes = set(scope.split())
            
            if not original_scopes.issuperset(requested_scopes):
                return Response(
                    {'error': 'invalid_scope', 'error_description': 'Cannot request more scopes than originally granted'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        with transaction.atomic():
            # Revoke the current token
            token.revoke()
            
            # Create new tokens
            new_token = OAuth2Token.objects.create(
                client=client,
                user=token.user,
                scope=scope,
                access_token_expires_at=timezone.now() + timezone.timedelta(
                    seconds=client.access_token_lifetime
                ),
                refresh_token_expires_at=timezone.now() + timezone.timedelta(
                    seconds=client.refresh_token_lifetime
                ) if 'refresh_token' in client.allowed_grant_types else None,
                client_ip=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log token refresh
            from audit.models import AuditLog
            AuditLog.objects.create(
                category='oauth2',
                event_type='oauth2_token_refreshed',
                user=token.user,
                details={
                    'client_id': client.client_id,
                    'client_name': client.name,
                    'scope': scope
                }
            )
            
            # Prepare response
            response_data = {
                'access_token': new_token.access_token,
                'token_type': 'bearer',
                'expires_in': client.access_token_lifetime,
            }
            
            if new_token.refresh_token:
                response_data['refresh_token'] = new_token.refresh_token
            
            if scope:
                response_data['scope'] = scope
            
            return Response(response_data)

class UserinfoView(APIView):
    """
    OAuth2 userinfo endpoint.
    """
    
    def get(self, request):
        """
        Get user information for the authenticated user.
        """
        # Get the access token from the Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return Response(
                {'error': 'invalid_token'},
                status=status.HTTP_401_UNAUTHORIZED,
                headers={'WWW-Authenticate': 'Bearer'}
            )
        
        token_value = auth_header.split(' ')[1]
        
        # Validate the token
        try:
            token = OAuth2Token.objects.get(access_token=token_value)
            
            if not token.is_access_token_valid():
                return Response(
                    {'error': 'invalid_token', 'error_description': 'Token is expired or revoked'},
                    status=status.HTTP_401_UNAUTHORIZED,
                    headers={'WWW-Authenticate': 'Bearer error="invalid_token"'}
                )
            
            # Check scope - 'openid' is required
            if token.scope and 'openid' not in token.scope.split():
                return Response(
                    {'error': 'insufficient_scope', 'error_description': 'Token does not have the required scope'},
                    status=status.HTTP_403_FORBIDDEN,
                    headers={'WWW-Authenticate': 'Bearer error="insufficient_scope" scope="openid"'}
                )
            
            # Return user info
            serializer = UserInfoSerializer(token.user)
            return Response(serializer.data)
            
        except OAuth2Token.DoesNotExist:
            return Response(
                {'error': 'invalid_token'},
                status=status.HTTP_401_UNAUTHORIZED,
                headers={'WWW-Authenticate': 'Bearer error="invalid_token"'}
            )

@api_view(['GET'])
def jwks_json(request):
    """
    JWKs endpoint for JSON Web Key Set.
    """
    # For HS256, we don't expose the secret, just return an empty key set
    # For RS256, we would include the public key
    return JsonResponse({"keys": []})

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_token(request):
    """
    Token revocation endpoint.
    """
    token = request.data.get('token')
    token_type_hint = request.data.get('token_type_hint', '')
    
    if not token:
        return Response(
            {'error': 'invalid_request', 'error_description': 'Token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Try to find the token
    filter_args = {}
    
    if token_type_hint == 'access_token':
        filter_args['access_token'] = token
    elif token_type_hint == 'refresh_token':
        filter_args['refresh_token'] = token
    else:
        # No hint or invalid hint, try both
        # Use Q objects for OR condition
        from django.db.models import Q
        oauth2_tokens = OAuth2Token.objects.filter(
            Q(access_token=token) | Q(refresh_token=token)
        )
    
    tokens_found = False
    
    # If token type hint was provided, try that specific type first
    if token_type_hint in ['access_token', 'refresh_token']:
        try:
            if token_type_hint == 'access_token':
                oauth2_token = OAuth2Token.objects.get(access_token=token)
            else:
                oauth2_token = OAuth2Token.objects.get(refresh_token=token)
            
            # Revoke the token
            oauth2_token.revoke()
            tokens_found = True
            
            # Log token revocation
            from audit.models import AuditLog
            AuditLog.objects.create(
                category='oauth2',
                event_type='oauth2_token_revoked',
                user=request.user,
                details={
                    'client_id': oauth2_token.client.client_id,
                    'client_name': oauth2_token.client.name,
                    'token_type_hint': token_type_hint
                }
            )
        except OAuth2Token.DoesNotExist:
            # If not found with the hint, try the other type
            pass
    
    # If not found with hint or no hint provided, try both types
    if not tokens_found:
        # Revoke all matching tokens
        count = oauth2_tokens.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        tokens_found = count > 0
    
    # The OAuth2 spec recommends always returning 200 even if token was not found
    return Response(status=status.HTTP_200_OK)