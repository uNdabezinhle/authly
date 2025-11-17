from rest_framework import serializers
from django_filters import rest_framework as filters
from .models import AuditLog

class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for audit log entries"""
    
    actor_name = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    risk_level_display = serializers.CharField(source='get_risk_level_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'actor', 'actor_email', 'actor_name', 'action', 'action_display',
            'resource', 'resource_id', 'resource_name', 'ip_address', 'user_agent',
            'session_id', 'request_id', 'timestamp', 'risk_level', 'risk_level_display',
            'success', 'error_message', 'metadata'
        ]
        read_only_fields = '__all__'  # Audit logs are read-only
    
    def get_actor_name(self, obj):
        """Get actor's full name if available"""
        if obj.actor:
            return f"{obj.actor.first_name} {obj.actor.last_name}".strip() or obj.actor.email
        return obj.actor_email or 'System'

class AuditLogFilterSet(filters.FilterSet):
    """Filter set for audit log API"""
    
    action = filters.ChoiceFilter(choices=AuditLog.ACTION_CHOICES)
    actor_email = filters.CharFilter(field_name='actor_email', lookup_expr='icontains')
    date_from = filters.DateTimeFilter(field_name='timestamp', lookup_expr='gte')
    date_to = filters.DateTimeFilter(field_name='timestamp', lookup_expr='lte')
    date = filters.DateFilter(field_name='timestamp__date')
    resource = filters.CharFilter(field_name='resource', lookup_expr='icontains')
    resource_id = filters.UUIDFilter(field_name='resource_id')
    risk_level = filters.ChoiceFilter(choices=AuditLog.RISK_CHOICES)
    success = filters.BooleanFilter()
    ip_address = filters.CharFilter()
    session_id = filters.CharFilter()
    
    class Meta:
        model = AuditLog
        fields = [
            'action', 'actor', 'actor_email', 'date_from', 'date_to', 'date',
            'resource', 'resource_id', 'risk_level', 'success', 'ip_address', 'session_id'
        ]

class AuditStatsSerializer(serializers.Serializer):
    """Serializer for audit statistics"""
    
    total_events = serializers.IntegerField()
    events_by_action = serializers.DictField()
    events_by_risk_level = serializers.DictField()
    failed_events = serializers.IntegerField()
    unique_users = serializers.IntegerField()
    unique_ips = serializers.IntegerField()
    date_range = serializers.DictField()
