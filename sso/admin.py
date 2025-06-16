# sso/admin.py

from django.contrib import admin
from .models import IdentityProvider, SSOUserMapping, SSOSession

@admin.register(IdentityProvider)
class IdentityProviderAdmin(admin.ModelAdmin):
    list_display = ('name', 'protocol', 'is_active', 'tenant', 'created_at', 'updated_at')
    list_filter = ('protocol', 'is_active', 'tenant')

@admin.register(SSOUserMapping)
class SSOUserMappingAdmin(admin.ModelAdmin):
    list_display = ('user', 'identity_provider', 'external_id', 'external_email', 'tenant', 'created_at', 'last_login')
    list_filter = ('identity_provider', 'tenant', 'created_at', 'last_login')

@admin.register(SSOSession)
class SSOSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'identity_provider', 'tenant', 'started_at', 'expires_at', 'is_active')
    list_filter = ('is_active', 'tenant', 'started_at', 'expires_at')
    search_fields = ('session_id', 'user_mapping__user__email', 'user_mapping__external_id')
    readonly_fields = ('started_at', 'logged_out_at')
    #raw_id_fields = ('user_mapping',)
    fieldsets = (
        (None, {
            'fields': ('user_mapping', 'session_id', 'is_active')
        }),
        ('Session Details', {
            'fields': ('started_at', 'expires_at', 'logged_out_at')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
    )
    
    def get_user(self, obj):
        return obj.user_mapping.user.email
    get_user.short_description = 'User'
    
    def get_provider(self, obj):
        return obj.user_mapping.identity_provider.name
    get_provider.short_description = 'Identity Provider'