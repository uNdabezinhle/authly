from rest_framework import serializers
from .models import IdentityProvider, FederatedUser, SAMLSession


class IdentityProviderSerializer(serializers.ModelSerializer):
    class Meta:
        model = IdentityProvider
        fields = [
            'id', 'name', 'slug', 'provider_type', 'status',
            'entity_id', 'metadata_url', 'sso_url', 'sls_url',
            'client_id', 'authorization_endpoint', 'token_endpoint', 
            'userinfo_endpoint', 'jwks_uri', 'issuer',
            'jit_enabled', 'jit_default_role', 'attribute_mapping',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'client_secret': {'write_only': True},
            'sp_private_key': {'write_only': True},
            'x509_cert': {'write_only': True},
            'sp_cert': {'write_only': True},
        }


class IdentityProviderCreateSerializer(serializers.ModelSerializer):
    """Separate serializer for creation with all sensitive fields"""
    
    class Meta:
        model = IdentityProvider
        fields = '__all__'
        extra_kwargs = {
            'client_secret': {'write_only': True},
            'sp_private_key': {'write_only': True},
        }


class FederatedUserSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    identity_provider_name = serializers.CharField(source='identity_provider.name', read_only=True)
    
    class Meta:
        model = FederatedUser
        fields = [
            'id', 'user_email', 'user_full_name', 'identity_provider_name',
            'external_user_id', 'external_username', 'external_email',
            'attributes', 'first_login', 'last_login'
        ]


class SAMLSessionSerializer(serializers.ModelSerializer):
    identity_provider_name = serializers.CharField(source='identity_provider.name', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = SAMLSession
        fields = [
            'id', 'session_id', 'identity_provider_name', 'user_email',
            'saml_request_id', 'relay_state', 'status',
            'created_at', 'completed_at', 'expires_at'
        ]


class SAMLInitiateSerializer(serializers.Serializer):
    """Serializer for SAML SSO initiation"""
    relay_state = serializers.CharField(required=False, help_text="Optional relay state for post-auth redirect")


class OIDCInitiateSerializer(serializers.Serializer):
    """Serializer for OIDC authentication initiation"""
    state = serializers.CharField(required=False, help_text="Optional state parameter for OIDC flow")
    nonce = serializers.CharField(required=False, help_text="Optional nonce for OIDC flow")