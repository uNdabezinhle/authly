from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'category', 'user', 'tenant', 'success')
    list_filter = ('category', 'event_type', 'tenant', 'user', 'success')
    search_fields = ('user__email', 'details')
    readonly_fields = ('hash', 'previous_hash')
