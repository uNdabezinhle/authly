# sso/serializers.py

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import IdentityProvider, SSOUserMapping, SSOSession

class IdentityProviderSerializer(serializers.ModelSerializer):
    """
    Serializer for the IdentityProvider model.
    """
    class Meta:
        model = IdentityProvider
        fields = [
            'id', 'name', 'description', 'protocol', 
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

class IdentityProviderDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the IdentityProvider model including config details.
    """
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = IdentityProvider
        fields = [
            'id', 'name', 'description', 'protocol', 
            'is_active', 'config', 'created_at', 'updated_at',
            'user_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'user_count']
    
    def get_user_count(self, obj):
        return obj.user_mappings.count()

class SSOUserMappingSerializer(serializers.ModelSerializer):
    """
    Serializer for the SSOUserMapping model.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    identity_provider_name = serializers.CharField(source='identity_provider.name', read_only=True)
    
    class Meta:
        model = SSOUserMapping
        fields = [
            'id', 'user', 'user_email', 'identity_provider', 
            'identity_provider_name', 'external_id', 'external_email',
            'external_username', 'created_at', 'updated_at', 'last_login'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_login']

class SSOSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for the SSOSession model.
    """
    user_email = serializers.EmailField(source='user_mapping.user.email', read_only=True)
    identity_provider_name = serializers.CharField(source='user_mapping.identity_provider.name', read_only=True)
    
    class Meta:
        model = SSOSession
        fields = [
            'id', 'user_mapping', 'user_email', 'identity_provider_name',
            'session_id', 'started_at', 'expires_at', 'is_active',
            'logged_out_at', 'ip_address', 'user_agent'
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