# sso/serializers.py

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import IdentityProvider, SSOUserMapping, SSOSession

class IdentityProviderSerializer(serializers.ModelSerializer):
    """
    Serializer for the IdentityProvider model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = IdentityProvider
        fields = [
            'id', 'tenant', 'name', 'protocol', 'metadata_url',
            'client_id', 'client_secret', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

class IdentityProviderDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the IdentityProvider model including config details.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = IdentityProvider
        fields = [
            'id', 'tenant', 'name', 'protocol', 'metadata_url',
            'client_id', 'client_secret', 'is_active', 'created_at', 'updated_at',
            'user_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'user_count']
    
    def get_user_count(self, obj):
        return obj.user_mappings.count()

class SSOUserMappingSerializer(serializers.ModelSerializer):
    """
    Serializer for the SSOUserMapping model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    identity_provider_name = serializers.CharField(source='identity_provider.name', read_only=True)
    
    class Meta:
        model = SSOUserMapping
        fields = [
            'id', 'tenant', 'user', 'user_email', 'identity_provider', 
            'identity_provider_name', 'external_id', 'external_email',
            'created_at', 'last_login'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_login']

class SSOSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for the SSOSession model.
    """
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    user_email = serializers.EmailField(source='user_mapping.user.email', read_only=True)
    identity_provider_name = serializers.CharField(source='user_mapping.identity_provider.name', read_only=True)
    
    class Meta:
        model = SSOSession
        fields = [
            'id', 'tenant', 'user', 'identity_provider', 'session_key',
            'started_at', 'expires_at', 'logged_out_at', 'is_active'
        ]
        read_only_fields = fields

# Serializers for SSO login flows
class SSOLoginInitSerializer(serializers.Serializer):
    """
    Serializer for initiating an SSO login flow.
    """
    provider_id = serializers.UUIDField(required=True)
    next = serializers.CharField(required=False, allow_blank=True)

class SSOLDAPLoginSerializer(serializers.Serializer):
    """
    Serializer for LDAP/Active Directory login.
    """
    provider_id = serializers.UUIDField(required=True)
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})
    next = serializers.CharField(required=False, allow_blank=True)

class SSOCallbackSerializer(serializers.Serializer):
    """
    Serializer for processing SSO callback data.
    """
    provider_id = serializers.UUIDField(required=True)
    code = serializers.CharField(required=False)
    state = serializers.CharField(required=False)
    
    class Meta:
        fields = ['provider_id', 'code', 'state']