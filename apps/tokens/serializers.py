import uuid
from rest_framework import serializers
from .models import TokenScope, ScopedToken, TokenIntrospection, TokenRevocation
from datetime import timedelta
from django.utils import timezone


class TokenScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenScope
        fields = [
            'id', 'name', 'description', 'resource_type', 'actions',
            'is_sensitive', 'requires_mfa', 'max_token_lifetime',
            'created_at', 'updated_at'
        ]


class ScopedTokenSerializer(serializers.ModelSerializer):
    scope_names = serializers.SerializerMethodField()
    jwt_token = serializers.SerializerMethodField()
    
    class Meta:
        model = ScopedToken
        fields = [
            'id', 'jti', 'token_type', 'audience', 'client_id',
            'scope_names', 'permissions', 'delegated_by',
            'issued_at', 'expires_at', 'not_before',
            'usage_count', 'max_uses', 'last_used_at',
            'is_active', 'jwt_token'
        ]
        read_only_fields = [
            'id', 'jti', 'issued_at', 'usage_count', 'last_used_at', 'jwt_token'
        ]
    
    def get_scope_names(self, obj):
        return obj.get_scope_names()
    
    def get_jwt_token(self, obj):
        # Only return JWT for active, valid tokens
        if obj.is_valid():
            return obj.generate_jwt()
        return None


class TokenCreateSerializer(serializers.Serializer):
    """Serializer for creating new scoped tokens"""
    
    audience = serializers.CharField(help_text="Intended audience for the token")
    scopes = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of scope names to grant"
    )
    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list,
        help_text="Specific permissions to grant"
    )
    client_id = serializers.CharField(required=False, help_text="Client requesting the token")
    
    # Time constraints
    expires_in = serializers.IntegerField(
        default=3600,
        help_text="Token lifetime in seconds (default: 1 hour)"
    )
    not_before = serializers.DateTimeField(
        required=False,
        help_text="Token not valid before this time (defaults to now)"
    )
    
    # Usage constraints
    max_uses = serializers.IntegerField(
        required=False,
        help_text="Maximum number of times token can be used"
    )
    
    def validate_scopes(self, value):
        """Validate that all requested scopes exist"""
        existing_scopes = TokenScope.objects.filter(name__in=value)
        if len(existing_scopes) != len(value):
            invalid_scopes = set(value) - set(existing_scopes.values_list('name', flat=True))
            raise serializers.ValidationError(f"Invalid scopes: {list(invalid_scopes)}")
        return value
    
    def validate_expires_in(self, value):
        """Validate token lifetime constraints"""
        if value < 60:  # Minimum 1 minute
            raise serializers.ValidationError("Token lifetime must be at least 60 seconds")
        if value > 86400 * 30:  # Maximum 30 days
            raise serializers.ValidationError("Token lifetime cannot exceed 30 days")
        return value
    
    def create(self, validated_data):
        user = self.context['request'].user
        tenant = self.context['request'].tenant
        
        # Create token
        expires_at = timezone.now() + timedelta(seconds=validated_data['expires_in'])
        not_before = validated_data.get('not_before', timezone.now())
        
        token = ScopedToken.objects.create(
            user=user,
            tenant=tenant,
            jti=str(uuid.uuid4()),
            audience=validated_data['audience'],
            client_id=validated_data.get('client_id', ''),
            permissions=validated_data.get('permissions', []),
            expires_at=expires_at,
            not_before=not_before,
            max_uses=validated_data.get('max_uses')
        )
        
        # Add scopes
        scopes = TokenScope.objects.filter(name__in=validated_data['scopes'])
        token.scopes.set(scopes)
        
        return token


class TokenIntrospectionSerializer(serializers.Serializer):
    """Serializer for token introspection responses"""
    
    active = serializers.BooleanField()
    jti = serializers.CharField(required=False)
    sub = serializers.CharField(required=False, help_text="Subject (user ID)")
    aud = serializers.CharField(required=False, help_text="Audience")
    iat = serializers.IntegerField(required=False, help_text="Issued at")
    exp = serializers.IntegerField(required=False, help_text="Expires at")
    nbf = serializers.IntegerField(required=False, help_text="Not before")
    
    # Custom claims
    tenant_id = serializers.CharField(required=False)
    token_type = serializers.CharField(required=False)
    scopes = serializers.ListField(child=serializers.CharField(), required=False)
    permissions = serializers.ListField(child=serializers.CharField(), required=False)
    usage_count = serializers.IntegerField(required=False)
    client_id = serializers.CharField(required=False)
    
    # Delegation info
    delegated_by = serializers.CharField(required=False)
    delegation_chain = serializers.JSONField(required=False)


class TokenRevocationSerializer(serializers.ModelSerializer):
    token_jti = serializers.CharField(source='token.jti', read_only=True)
    revoked_by_email = serializers.EmailField(source='revoked_by.email', read_only=True)
    
    class Meta:
        model = TokenRevocation
        fields = [
            'id', 'token_jti', 'reason', 'notes', 'revoked_by_email',
            'revoked_at', 'ip_address', 'user_agent'
        ]
        read_only_fields = ['id', 'revoked_at']


class TokenIntrospectionRequestSerializer(serializers.Serializer):
    """Serializer for token introspection requests"""
    
    token = serializers.CharField(help_text="JWT token to introspect")
    
    def validate_token(self, value):
        """Basic token format validation"""
        if not value or len(value.split('.')) != 3:
            raise serializers.ValidationError("Invalid JWT token format")
        return value