# sso/admin.py

from django.contrib import admin
from .models import IdentityProvider, SSOUserMapping, SSOSession

@admin.register(IdentityProvider)
class IdentityProviderAdmin(admin.ModelAdmin):
    list_display = ('name', 'protocol', 'is_active', 'created_at', 'updated_at')
    list_filter = ('protocol', 'is_active')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'protocol', 'is_active')
        }),
        ('Configuration', {
            'fields': ('config',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(SSOUserMapping)
class SSOUserMappingAdmin(admin.ModelAdmin):
    list_display = ('user', 'identity_provider', 'external_id', 'external_email', 'created_at', 'last_login')
    list_filter = ('identity_provider', 'created_at', 'last_login')
    search_fields = ('user__email', 'external_id', 'external_email', 'external_username')
    readonly_fields = ('created_at', 'updated_at', 'last_login')
    raw_id_fields = ('user', 'identity_provider')
    fieldsets = (
        (None, {
            'fields': ('user', 'identity_provider')
        }),
        ('External Identity', {
            'fields': ('external_id', 'external_email', 'external_username')
        }),
        ('Profile Data', {
            'fields': ('profile_data',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'last_login'),
            'classes': ('collapse',)
        }),
    )

@admin.register(SSOSession)
class SSOSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_user', 'get_provider', 'started_at', 'expires_at', 'is_active')
    list_filter = ('is_active', 'started_at', 'expires_at', 'logged_out_at')
    search_fields = ('session_id', 'user_mapping__user__email', 'user_mapping__external_id')
    readonly_fields = ('started_at', 'logged_out_at')
    raw_id_fields = ('user_mapping',)
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