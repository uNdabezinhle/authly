import uuid
import base64
import jwt
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .models import IdentityProvider, FederatedUser, SAMLSession
from .serializers import (
    IdentityProviderSerializer, IdentityProviderCreateSerializer,
    FederatedUserSerializer, SAMLSessionSerializer,
    SAMLInitiateSerializer, OIDCInitiateSerializer
)

User = get_user_model()


class IdentityProviderViewSet(viewsets.ModelViewSet):
    """Manage Identity Providers for federation"""
    queryset = IdentityProvider.objects.all()
    serializer_class = IdentityProviderSerializer
    lookup_field = 'slug'
    
    def get_serializer_class(self):
        if self.action == 'create':
            return IdentityProviderCreateSerializer
        return IdentityProviderSerializer
    
    @action(detail=True, methods=['post'], permission_classes=[AllowAny])
    def test_connection(self, request, slug=None):
        """Test connection to IdP"""
        idp = self.get_object()
        
        if idp.provider_type == 'saml':
            # Test SAML metadata endpoint
            try:
                import requests
                response = requests.get(idp.metadata_url, timeout=10)
                if response.status_code == 200:
                    return Response({'status': 'success', 'message': 'SAML metadata accessible'})
                else:
                    return Response({'status': 'error', 'message': f'HTTP {response.status_code}'})
            except Exception as e:
                return Response({'status': 'error', 'message': str(e)})
                
        elif idp.provider_type == 'oidc':
            # Test OIDC discovery endpoint
            try:
                import requests
                discovery_url = f"{idp.issuer}/.well-known/openid-configuration"
                response = requests.get(discovery_url, timeout=10)
                if response.status_code == 200:
                    return Response({'status': 'success', 'message': 'OIDC discovery endpoint accessible'})
                else:
                    return Response({'status': 'error', 'message': f'HTTP {response.status_code}'})
            except Exception as e:
                return Response({'status': 'error', 'message': str(e)})
        
        return Response({'status': 'error', 'message': 'Unknown provider type'})


class FederatedUserViewSet(viewsets.ReadOnlyModelViewSet):
    """View federated user mappings"""
    queryset = FederatedUser.objects.all()
    serializer_class = FederatedUserSerializer
    
    def get_queryset(self):
        queryset = super().get_queryset()
        idp_slug = self.request.query_params.get('idp')
        if idp_slug:
            queryset = queryset.filter(identity_provider__slug=idp_slug)
        return queryset


@api_view(['POST'])
@permission_classes([AllowAny])
def initiate_sso(request, tenant_slug, idp_slug):
    """Initiate SSO authentication with an IdP"""
    
    try:
        idp = IdentityProvider.objects.get(slug=idp_slug, status='active')
    except IdentityProvider.DoesNotExist:
        return Response({'error': 'Identity provider not found'}, 
                       status=status.HTTP_404_NOT_FOUND)
    
    if idp.provider_type == 'saml':
        return initiate_saml_sso(request, tenant_slug, idp)
    elif idp.provider_type == 'oidc':
        return initiate_oidc_sso(request, tenant_slug, idp)
    else:
        return Response({'error': 'Unsupported provider type'}, 
                       status=status.HTTP_400_BAD_REQUEST)


def initiate_saml_sso(request, tenant_slug, idp):
    """Initiate SAML SSO flow"""
    
    # Generate SAML Request ID and session
    request_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    
    # Create SAML session
    saml_session = SAMLSession.objects.create(
        session_id=session_id,
        identity_provider=idp,
        saml_request_id=request_id,
        relay_state=request.data.get('relay_state', ''),
        expires_at=timezone.now() + timedelta(minutes=10)
    )
    
    # Build SAML AuthnRequest (simplified)
    acs_url = request.build_absolute_uri(
        reverse('federation:saml_acs', kwargs={'tenant_slug': tenant_slug, 'idp_slug': idp.slug})
    )
    
    saml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{timezone.now().isoformat()}"
    Destination="{idp.sso_url}"
    AssertionConsumerServiceURL="{acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{acs_url}</saml:Issuer>
</samlp:AuthnRequest>"""
    
    # Base64 encode the request
    encoded_request = base64.b64encode(saml_request.encode()).decode()
    
    # Build redirect URL
    params = {
        'SAMLRequest': encoded_request,
        'RelayState': saml_session.relay_state
    }
    redirect_url = f"{idp.sso_url}?{urlencode(params)}"
    
    return Response({
        'redirect_url': redirect_url,
        'session_id': session_id,
        'request_id': request_id
    })


def initiate_oidc_sso(request, tenant_slug, idp):
    """Initiate OIDC authentication flow"""
    
    # Generate state and nonce
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    
    # Build redirect URI
    redirect_uri = request.build_absolute_uri(
        reverse('federation:oidc_callback', kwargs={'tenant_slug': tenant_slug, 'idp_slug': idp.slug})
    )
    
    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': idp.client_id,
        'redirect_uri': redirect_uri,
        'scope': 'openid profile email',
        'state': state,
        'nonce': nonce,
    }
    
    authorization_url = f"{idp.authorization_endpoint}?{urlencode(params)}"
    
    return Response({
        'authorization_url': authorization_url,
        'state': state,
        'nonce': nonce
    })


@csrf_exempt
@require_http_methods(["POST"])
def saml_acs(request, tenant_slug, idp_slug):
    """SAML Assertion Consumer Service"""
    
    try:
        idp = IdentityProvider.objects.get(slug=idp_slug, status='active')
    except IdentityProvider.DoesNotExist:
        return HttpResponse('Identity provider not found', status=404)
    
    # Get SAML response from POST data
    saml_response = request.POST.get('SAMLResponse')
    relay_state = request.POST.get('RelayState', '')
    
    if not saml_response:
        return HttpResponse('Missing SAML response', status=400)
    
    try:
        # Decode SAML response (simplified - in production use proper SAML library)
        decoded_response = base64.b64decode(saml_response).decode()
        
        # Extract user info from SAML assertion (simplified)
        # In production, use python3-saml or similar library for proper parsing/validation
        
        # Mock extraction for demo - replace with proper SAML parsing
        user_info = {
            'email': 'user@example.com',  # Extract from SAML
            'first_name': 'John',         # Extract from SAML
            'last_name': 'Doe',           # Extract from SAML
            'external_id': 'saml_user_123' # Extract from SAML
        }
        
        # Create or get user
        user = create_or_update_federated_user(idp, user_info)
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Return success with tokens (in production, handle via proper redirect)
        return HttpResponse(f"""
        <html><body>
        <h2>SAML Authentication Successful</h2>
        <p>Access Token: {refresh.access_token}</p>
        <p>Refresh Token: {refresh}</p>
        <script>
        // In production, handle token storage properly
        if (window.opener) {{
            window.opener.postMessage({{
                type: 'saml_success',
                access_token: '{refresh.access_token}',
                refresh_token: '{refresh}'
            }}, '*');
            window.close();
        }}
        </script>
        </body></html>
        """)
        
    except Exception as e:
        return HttpResponse(f'SAML processing error: {str(e)}', status=400)


@api_view(['GET'])
@permission_classes([AllowAny])
def oidc_callback(request, tenant_slug, idp_slug):
    """OIDC callback endpoint"""
    
    try:
        idp = IdentityProvider.objects.get(slug=idp_slug, status='active')
    except IdentityProvider.DoesNotExist:
        return Response({'error': 'Identity provider not found'}, 
                       status=status.HTTP_404_NOT_FOUND)
    
    # Get authorization code and state
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    if not code:
        return Response({'error': 'Missing authorization code'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Exchange code for tokens
        import requests
        
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': idp.client_id,
            'client_secret': idp.client_secret,
            'code': code,
            'redirect_uri': request.build_absolute_uri(request.path)
        }
        
        response = requests.post(idp.token_endpoint, data=token_data)
        token_response = response.json()
        
        if 'access_token' not in token_response:
            return Response({'error': 'Token exchange failed'}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Get user info
        headers = {'Authorization': f'Bearer {token_response["access_token"]}'}
        user_response = requests.get(idp.userinfo_endpoint, headers=headers)
        user_info = user_response.json()
        
        # Create or update federated user
        user = create_or_update_federated_user(idp, {
            'email': user_info.get('email'),
            'first_name': user_info.get('given_name', ''),
            'last_name': user_info.get('family_name', ''),
            'external_id': user_info.get('sub')
        })
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })
        
    except Exception as e:
        return Response({'error': f'OIDC processing error: {str(e)}'}, 
                       status=status.HTTP_400_BAD_REQUEST)


def create_or_update_federated_user(idp, user_info):
    """Create or update a federated user"""
    
    # Try to find existing federated user
    try:
        federated_user = FederatedUser.objects.get(
            identity_provider=idp,
            external_user_id=user_info['external_id']
        )
        user = federated_user.user
        
        # Update user info if changed
        updated = False
        if user.email != user_info.get('email'):
            user.email = user_info.get('email', user.email)
            updated = True
        if user.first_name != user_info.get('first_name'):
            user.first_name = user_info.get('first_name', user.first_name)
            updated = True
        if user.last_name != user_info.get('last_name'):
            user.last_name = user_info.get('last_name', user.last_name)
            updated = True
            
        if updated:
            user.save()
            
        # Update last login
        federated_user.last_login = timezone.now()
        federated_user.save()
        
    except FederatedUser.DoesNotExist:
        # Create new user if JIT is enabled
        if not idp.jit_enabled:
            raise ValueError("User not found and JIT provisioning is disabled")
        
        # Create new user
        user = User.objects.create_user(
            username=user_info.get('email'),
            email=user_info.get('email'),
            first_name=user_info.get('first_name', ''),
            last_name=user_info.get('last_name', ''),
            email_verified=True  # Trust IdP verification
        )
        
        # Create federated user link
        federated_user = FederatedUser.objects.create(
            user=user,
            identity_provider=idp,
            external_user_id=user_info['external_id'],
            external_username=user_info.get('username', ''),
            external_email=user_info.get('email', ''),
            attributes=user_info
        )
        
        # Assign default role if configured
        if idp.jit_default_role:
            try:
                from apps.roles.models import Role
                role = Role.objects.get(name=idp.jit_default_role)
                user.roles.add(role)
            except:
                pass  # Role doesn't exist, continue
    
    return user