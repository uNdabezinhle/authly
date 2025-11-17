from rest_framework import serializers
from .models import APIKey


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for listing API keys (hides full key)"""
    masked_key = serializers.SerializerMethodField()
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'prefix', 'masked_key', 'scopes', 
            'expires_at', 'created_at', 'is_active'
        ]
        read_only_fields = ['id', 'prefix', 'created_at']

    def get_masked_key(self, obj):
        return f"{obj.prefix}_{'*' * 32}"


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API keys"""
    
    class Meta:
        model = APIKey
        fields = ['name', 'scopes', 'expires_at']

    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Name cannot be empty.")
        return value.strip()

    def validate_scopes(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Scopes must be a list.")
        
        # Define valid scopes
        valid_scopes = [
            'read', 'write', 'admin', 
            'users:read', 'users:write',
            'roles:read', 'roles:write',
            'webhooks:read', 'webhooks:write',
            'audit:read'
        ]
        
        for scope in value:
            if scope not in valid_scopes:
                raise serializers.ValidationError(f"Invalid scope: {scope}")
        
        return value

    def create(self, validated_data):
        user = self.context['request'].user
        tenant = self.context['request'].tenant
        
        # Create API key with generated prefix and hashed key
        api_key, raw_key = APIKey.create_key(
            user=user,
            tenant=tenant,
            **validated_data
        )
        
        # Add the raw key to the serialized response
        api_key.raw_key = raw_key
        return api_key


class APIKeyDetailSerializer(serializers.ModelSerializer):
    """Serializer for API key details after creation (shows full key once)"""
    raw_key = serializers.CharField(read_only=True)
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'prefix', 'raw_key', 'scopes', 
            'expires_at', 'created_at', 'is_active'
        ]
        read_only_fields = ['id', 'prefix', 'raw_key', 'created_at']
