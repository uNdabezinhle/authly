# api_keys/serializers.py

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import APIKey, APIKeyUsage

class APIKeySerializer(serializers.ModelSerializer):
    """
    Serializer for the APIKey model (basic info).
    """
    days_until_expiry = serializers.SerializerMethodField()
    user_email = serializers.SerializerMethodField()
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'prefix', 'user', 'user_email', 'scopes', 'created_at', 
            'expires_at', 'last_used_at', 'is_active', 'description', 
            'days_until_expiry'
        ]
        read_only_fields = ['id', 'prefix', 'user', 'created_at', 'last_used_at']
    
    def get_days_until_expiry(self, obj):
        if not obj.expires_at:
            return None
        from django.utils import timezone
        import math
        delta = obj.expires_at - timezone.now()
        return max(0, math.ceil(delta.total_seconds() / 86400))  # Convert to days and round up
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None

class APIKeyCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new API key.
    """
    key = serializers.CharField(read_only=True)
    expires_in_days = serializers.IntegerField(write_only=True, required=False, min_value=1, max_value=365)
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key', 'scopes', 'description', 'allowed_ips', 
            'allowed_referers', 'rate_limit_requests', 'rate_limit_period',
            'expires_in_days'
        ]
        read_only_fields = ['id', 'key']
    
    def create(self, validated_data):
        # Handle expiry date calculation
        expires_in_days = validated_data.pop('expires_in_days', None)
        
        # Create the API key
        api_key = APIKey(**validated_data)
        
        # Set expiry date if provided
        if expires_in_days:
            from django.utils import timezone
            import datetime
            api_key.expires_at = timezone.now() + datetime.timedelta(days=expires_in_days)
        
        api_key.save()
        
        # Include the full key in the serialized response
        self.context['key'] = api_key.key
        
        return api_key
    
    def to_representation(self, instance):
        """
        Include the full API key in the response, but only once during creation.
        """
        representation = super().to_representation(instance)
        
        # Include the full key from context if present
        if 'key' in self.context:
            representation['key'] = self.context['key']
        
        return representation

class APIKeyDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the APIKey model.
    """
    days_until_expiry = serializers.SerializerMethodField()
    user_email = serializers.SerializerMethodField()
    usage_count = serializers.SerializerMethodField()
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'prefix', 'user', 'user_email', 'scopes', 'created_at', 
            'expires_at', 'last_used_at', 'is_active', 'description', 
            'allowed_ips', 'allowed_referers', 'rate_limit_requests', 
            'rate_limit_period', 'days_until_expiry', 'usage_count'
        ]
        read_only_fields = ['id', 'prefix', 'user', 'created_at', 'last_used_at']
    
    def get_days_until_expiry(self, obj):
        if not obj.expires_at:
            return None
        from django.utils import timezone
        import math
        delta = obj.expires_at - timezone.now()
        return max(0, math.ceil(delta.total_seconds() / 86400))  # Convert to days and round up
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None
    
    def get_usage_count(self, obj):
        return obj.usage_logs.count()

class APIKeyUsageSerializer(serializers.ModelSerializer):
    """
    Serializer for the APIKeyUsage model.
    """
    class Meta:
        model = APIKeyUsage
        fields = [
            'id', 'timestamp', 'endpoint', 'method', 'ip_address', 
            'user_agent', 'response_status', 'response_time_ms'
        ]
        read_only_fields = fields