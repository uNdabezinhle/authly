# oauth2/serializers.py

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

class OAuth2ClientSerializer(serializers.ModelSerializer):
    """
    Serializer for the OAuth2Client model.
    """
    user_email = serializers.SerializerMethodField()
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    
    class Meta:
        model = OAuth2Client
        fields = [
            'id', 'name', 'client_id', 'client_type', 'allowed_grant_types',
            'user', 'user_email', 'redirect_uris', 'post_logout_redirect_uris',
            'allowed_scopes', 'created_at', 'updated_at', 'is_active', 
            'description', 'logo_url', 'website_url', 'privacy_policy_url', 
            'terms_of_service_url', 'jwt_algorithm', 'access_token_lifetime',
            'refresh_token_lifetime'
        ]
        read_only_fields = [
            'id', 'client_id', 'user', 'created_at', 'updated_at'
        ]
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None

class OAuth2ClientCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new OAuth2 client.
    """
    client_secret = serializers.CharField(read_only=True)
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    
    class Meta:
        model = OAuth2Client
        fields = [
            'id', 'name', 'client_type', 'allowed_grant_types', 'redirect_uris',
            'post_logout_redirect_uris', 'allowed_scopes', 'description', 
            'logo_url', 'website_url', 'privacy_policy_url', 
            'terms_of_service_url', 'jwt_algorithm', 'access_token_lifetime',
            'refresh_token_lifetime', 'client_id', 'client_secret'
        ]
        read_only_fields = ['id', 'client_id', 'client_secret']
    
    def create(self, validated_data):
        client = OAuth2Client(**validated_data)
        client.save()
        
        # Store client_secret in context for one-time display
        if client.client_type == 'confidential':
            self.context['client_secret'] = client.client_secret
        
        return client
    
    def to_representation(self, instance):
        """
        Include the client secret in the response, but only once during creation.
        """
        representation = super().to_representation(instance)
        
        # Include the client secret from context if present
        if 'client_secret' in self.context:
            representation['client_secret'] = self.context['client_secret']
        
        return representation

class OAuth2ClientDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for the OAuth2Client model.
    """
    user_email = serializers.SerializerMethodField()
    active_tokens_count = serializers.SerializerMethodField()
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    
    class Meta:
        model = OAuth2Client
        fields = [
            'id', 'name', 'client_id', 'client_type', 'allowed_grant_types',
            'user', 'user_email', 'redirect_uris', 'post_logout_redirect_uris',
            'allowed_scopes', 'created_at', 'updated_at', 'is_active', 
            'description', 'logo_url', 'website_url', 'privacy_policy_url', 
            'terms_of_service_url', 'jwt_algorithm', 'access_token_lifetime',
            'refresh_token_lifetime', 'active_tokens_count'
        ]
        read_only_fields = [
            'id', 'client_id', 'user', 'created_at', 'updated_at', 'active_tokens_count'
        ]
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None
    
    def get_active_tokens_count(self, obj):
        return OAuth2Token.objects.filter(
            client=obj,
            access_token_expires_at__gt=timezone.now(),
            revoked_at__isnull=True
        ).count()

class OAuth2AuthorizeSerializer(serializers.Serializer):
    """
    Serializer for OAuth2 authorization request validation.
    """
    client_id = serializers.CharField(required=True)
    response_type = serializers.CharField(required=True)
    redirect_uri = serializers.CharField(required=True)
    scope = serializers.CharField(required=False, allow_blank=True)
    state = serializers.CharField(required=False, allow_blank=True)
    code_challenge = serializers.CharField(required=False, allow_blank=True)
    code_challenge_method = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        client_id = attrs.get('client_id')
        response_type = attrs.get('response_type')
        redirect_uri = attrs.get('redirect_uri')
        scope = attrs.get('scope', '')
        
        # Check if client exists
        try:
            client = OAuth2Client.objects.get(client_id=client_id, is_active=True)
        except OAuth2Client.DoesNotExist:
            raise serializers.ValidationError(_("Invalid client_id"))
        
        # Check response_type
        if response_type not in ['code', 'token']:
            raise serializers.ValidationError(_("Unsupported response_type"))
        
        # Check if the client supports the requested grant type
        if response_type == 'code' and 'authorization_code' not in client.allowed_grant_types:
            raise serializers.ValidationError(_("Client does not support authorization_code flow"))
        if response_type == 'token' and 'implicit' not in client.allowed_grant_types:
            raise serializers.ValidationError(_("Client does not support implicit flow"))
        
        # Check redirect_uri
        if not client.is_valid_redirect_uri(redirect_uri):
            raise serializers.ValidationError(_("Invalid redirect_uri"))
        
        # Check scope
        if scope and not client.is_valid_scope(scope):
            raise serializers.ValidationError(_("Invalid scope"))
        
        # Add client to validated data
        attrs['client'] = client
        
        return attrs

class OAuth2TokenExchangeSerializer(serializers.Serializer):
    """
    Serializer for OAuth2 token exchange (authorization code flow).
    """
    grant_type = serializers.CharField(required=True)
    code = serializers.CharField(required=False)
    redirect_uri = serializers.CharField(required=False)
    client_id = serializers.CharField(required=True)
    client_secret = serializers.CharField(required=False, allow_blank=True)
    code_verifier = serializers.CharField(required=False, allow_blank=True)
    refresh_token = serializers.CharField(required=False)
    scope = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        grant_type = attrs.get('grant_type')
        client_id = attrs.get('client_id')
        client_secret = attrs.get('client_secret', '')
        
        # Check if client exists
        try:
            client = OAuth2Client.objects.get(client_id=client_id, is_active=True)
        except OAuth2Client.DoesNotExist:
            raise serializers.ValidationError(_("Invalid client_id"))
        
        # Check client authentication for confidential clients
        if client.client_type == 'confidential' and not client_secret:
            raise serializers.ValidationError(_("client_secret is required for confidential clients"))
        
        if client.client_type == 'confidential' and client.client_secret != client_secret:
            raise serializers.ValidationError(_("Invalid client_secret"))
        
        # Check grant type
        if grant_type not in client.allowed_grant_types:
            raise serializers.ValidationError(_("Unsupported grant_type"))
        
        # Validate grant type specific parameters
        if grant_type == 'authorization_code':
            code = attrs.get('code')
            redirect_uri = attrs.get('redirect_uri')
            code_verifier = attrs.get('code_verifier')
            
            if not code:
                raise serializers.ValidationError(_("code is required for authorization_code grant"))
            
            if not redirect_uri:
                raise serializers.ValidationError(_("redirect_uri is required for authorization_code grant"))
            
            # Check if the authorization code exists and is valid
            try:
                auth_code = OAuth2AuthorizationCode.objects.get(code=code, client=client)
                
                if not auth_code.is_valid():
                    raise serializers.ValidationError(_("Authorization code is expired or has been used"))
                
                if auth_code.redirect_uri != redirect_uri:
                    raise serializers.ValidationError(_("redirect_uri does not match the one used for the authorization code"))
                
                # Check PKCE if used
                if auth_code.code_challenge and not code_verifier:
                    raise serializers.ValidationError(_("code_verifier is required for PKCE"))
                
                if auth_code.code_challenge and code_verifier:
                    # Verify the code challenge
                    import hashlib
                    import base64
                    
                    if auth_code.code_challenge_method == 'S256':
                        # SHA-256 hash
                        code_challenge = base64.urlsafe_b64encode(
                            hashlib.sha256(code_verifier.encode()).digest()
                        ).decode().rstrip('=')
                    else:
                        # Plain
                        code_challenge = code_verifier
                    
                    if code_challenge != auth_code.code_challenge:
                        raise serializers.ValidationError(_("Invalid code_verifier"))
                
                # Add auth_code to validated data
                attrs['auth_code'] = auth_code
                
            except OAuth2AuthorizationCode.DoesNotExist:
                raise serializers.ValidationError(_("Invalid authorization code"))
                
        elif grant_type == 'refresh_token':
            refresh_token = attrs.get('refresh_token')
            
            if not refresh_token:
                raise serializers.ValidationError(_("refresh_token is required for refresh_token grant"))
            
            # Check if the refresh token exists and is valid
            try:
                token = OAuth2Token.objects.get(refresh_token=refresh_token, client=client)
                
                if not token.is_refresh_token_valid():
                    raise serializers.ValidationError(_("Refresh token is expired or has been revoked"))
                
                # Add token to validated data
                attrs['token'] = token
                
            except OAuth2Token.DoesNotExist:
                raise serializers.ValidationError(_("Invalid refresh token"))
        
        # Add client to validated data
        attrs['client'] = client
        
        return attrs

class OAuth2TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for the OAuth2Token model.
    """
    class Meta:
        model = OAuth2Token
        fields = [
            'id', 'access_token', 'refresh_token', 'token_type', 
            'scope', 'created_at', 'access_token_expires_at', 
            'refresh_token_expires_at'
        ]
        read_only_fields = fields

class UserInfoSerializer(serializers.Serializer):
    """
    Serializer for the OAuth2 userinfo endpoint.
    """
    sub = serializers.CharField(source='id')
    email = serializers.EmailField()
    name = serializers.CharField(source='get_full_name')
    given_name = serializers.CharField(source='first_name')
    family_name = serializers.CharField(source='last_name')
    email_verified = serializers.BooleanField()
    
    class Meta:
        fields = ['sub', 'email', 'name', 'given_name', 'family_name', 'email_verified']
        read_only_fields = fields