from django.contrib import admin
from .models import TokenScope, ScopedToken, TokenIntrospection, TokenRevocation


@admin.register(TokenScope)
class TokenScopeAdmin(admin.ModelAdmin):
    list_display = ['name', 'resource_type', 'is_sensitive', 'requires_mfa', 'max_token_lifetime']
    list_filter = ['resource_type', 'is_sensitive', 'requires_mfa']
    search_fields = ['name', 'description', 'resource_type']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(ScopedToken)
class ScopedTokenAdmin(admin.ModelAdmin):
    list_display = ['jti', 'user', 'token_type', 'audience', 'is_active', 'usage_count', 'expires_at']
    list_filter = ['token_type', 'is_active', 'issued_at', 'expires_at']
    search_fields = ['jti', 'user__email', 'audience', 'client_id']
    readonly_fields = ['id', 'jti', 'issued_at', 'usage_count', 'last_used_at']
    filter_horizontal = ['scopes']
    
    fieldsets = (
        ('Token Identity', {
            'fields': ('jti', 'token_type', 'audience', 'client_id')
        }),
        ('User & Tenant', {
            'fields': ('user', 'tenant')
        }),
        ('Permissions', {
            'fields': ('scopes', 'permissions')
        }),
        ('Delegation', {
            'fields': ('delegated_by', 'delegation_chain'),
            'classes': ('collapse',)
        }),
        ('Constraints', {
            'fields': ('expires_at', 'not_before', 'max_uses')
        }),
        ('Usage Tracking', {
            'fields': ('usage_count', 'last_used_at', 'last_used_ip'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('is_active', 'revoked_at', 'revoked_by', 'revocation_reason')
        }),
    )


@admin.register(TokenIntrospection)
class TokenIntrospectionAdmin(admin.ModelAdmin):
    list_display = ['token', 'requested_at', 'was_valid', 'requester_ip', 'endpoint']
    list_filter = ['was_valid', 'requested_at']
    search_fields = ['token__jti', 'requester_ip', 'endpoint']
    readonly_fields = ['id', 'requested_at']


@admin.register(TokenRevocation)
class TokenRevocationAdmin(admin.ModelAdmin):
    list_display = ['token', 'reason', 'revoked_by', 'revoked_at']
    list_filter = ['reason', 'revoked_at']
    search_fields = ['token__jti', 'revoked_by__email', 'notes']
    readonly_fields = ['id', 'revoked_at']