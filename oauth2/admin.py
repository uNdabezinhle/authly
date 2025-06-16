from django.contrib import admin
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

@admin.register(OAuth2Client)
class OAuth2ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'client_id', 'user', 'tenant', 'is_active', 'created_at')
    list_filter = ('tenant', 'is_active', 'client_type')
    search_fields = ('name', 'client_id', 'user__email')

@admin.register(OAuth2AuthorizationCode)
class OAuth2AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ('code', 'client', 'user', 'tenant', 'is_used', 'expires_at')
    list_filter = ('tenant', 'is_used')
    search_fields = ('code', 'client__name', 'user__email')

@admin.register(OAuth2Token)
class OAuth2TokenAdmin(admin.ModelAdmin):
    list_display = ('access_token', 'client', 'user', 'tenant', 'revoked_at', 'access_token_expires_at')
    list_filter = ('tenant', 'revoked_at')
    search_fields = ('access_token', 'refresh_token', 'client__name', 'user__email')
