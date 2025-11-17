from django.contrib import admin
from .models import IdentityProvider, FederatedUser, SAMLSession


@admin.register(IdentityProvider)
class IdentityProviderAdmin(admin.ModelAdmin):
    list_display = ['name', 'provider_type', 'status', 'jit_enabled', 'created_at']
    list_filter = ['provider_type', 'status', 'jit_enabled']
    search_fields = ['name', 'slug', 'entity_id']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'provider_type', 'status')
        }),
        ('SAML Configuration', {
            'fields': ('entity_id', 'metadata_url', 'sso_url', 'sls_url', 'x509_cert', 'sp_cert', 'sp_private_key'),
            'classes': ('collapse',)
        }),
        ('OIDC Configuration', {
            'fields': ('client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'issuer'),
            'classes': ('collapse',)
        }),
        ('Provisioning', {
            'fields': ('jit_enabled', 'jit_default_role', 'attribute_mapping')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(FederatedUser)
class FederatedUserAdmin(admin.ModelAdmin):
    list_display = ['user', 'identity_provider', 'external_username', 'external_email', 'first_login', 'last_login']
    list_filter = ['identity_provider', 'first_login', 'last_login']
    search_fields = ['user__email', 'external_username', 'external_email', 'external_user_id']
    readonly_fields = ['id', 'first_login', 'last_login']


@admin.register(SAMLSession)
class SAMLSessionAdmin(admin.ModelAdmin):
    list_display = ['session_id', 'identity_provider', 'user', 'status', 'created_at', 'expires_at']
    list_filter = ['identity_provider', 'status', 'created_at']
    search_fields = ['session_id', 'saml_request_id', 'user__email']
    readonly_fields = ['id', 'created_at', 'completed_at']