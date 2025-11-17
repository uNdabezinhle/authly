from rest_framework import serializers
from django_filters import rest_framework as filters
from .models import Webhook, WebhookDelivery

class WebhookSerializer(serializers.ModelSerializer):
    """Serializer for webhook configuration"""
    
    supported_events = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        source='get_supported_events',
        help_text="List of all supported event types"
    )
    success_rate = serializers.SerializerMethodField()
    
    class Meta:
        model = Webhook
        fields = [
            'id', 'name', 'url', 'events', 'is_active', 'timeout_seconds',
            'max_retries', 'retry_delay_seconds', 'created_at', 'updated_at',
            'last_triggered_at', 'last_success_at', 'total_deliveries',
            'successful_deliveries', 'failed_deliveries', 'success_rate',
            'supported_events'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'last_triggered_at',
            'last_success_at', 'total_deliveries', 'successful_deliveries',
            'failed_deliveries'
        ]
    
    def get_success_rate(self, obj):
        """Calculate webhook success rate"""
        if obj.total_deliveries == 0:
            return None
        return round((obj.successful_deliveries / obj.total_deliveries) * 100, 2)
    
    def get_supported_events(self, obj):
        """Get list of all supported event types"""
        return [choice[0] for choice in Webhook.EVENT_CHOICES]
    
    def validate_events(self, value):
        """Validate that all events are supported"""
        supported = [choice[0] for choice in Webhook.EVENT_CHOICES]
        invalid_events = [event for event in value if event not in supported]
        
        if invalid_events:
            raise serializers.ValidationError(
                f"Unsupported events: {', '.join(invalid_events)}. "
                f"Supported events: {', '.join(supported)}"
            )
        
        return value
    
    def validate_url(self, value):
        """Validate webhook URL"""
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("URL must start with http:// or https://")
        return value

class WebhookCreateSerializer(WebhookSerializer):
    """Serializer for creating webhooks (includes secret in response)"""
    
    secret = serializers.CharField(read_only=True, help_text="Auto-generated HMAC secret")
    
    class Meta(WebhookSerializer.Meta):
        fields = WebhookSerializer.Meta.fields + ['secret']

class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for webhook delivery records"""
    
    webhook_name = serializers.CharField(source='webhook.name', read_only=True)
    webhook_url = serializers.CharField(source='webhook.url', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration_ms = serializers.SerializerMethodField()
    
    class Meta:
        model = WebhookDelivery
        fields = [
            'id', 'webhook_name', 'webhook_url', 'event_type', 'event_id',
            'status', 'status_display', 'response_status', 'response_body',
            'created_at', 'scheduled_at', 'attempted_at', 'completed_at',
            'attempt_count', 'max_attempts', 'next_retry_at',
            'error_message', 'duration_ms'
        ]
        read_only_fields = '__all__'  # Delivery records are read-only
    
    def get_duration_ms(self, obj):
        """Calculate delivery duration in milliseconds"""
        if obj.attempted_at and obj.completed_at:
            return int((obj.completed_at - obj.attempted_at).total_seconds() * 1000)
        return None

class WebhookDeliveryFilterSet(filters.FilterSet):
    """Filter set for webhook delivery API"""
    
    status = filters.ChoiceFilter(choices=WebhookDelivery.STATUS_CHOICES)
    event_type = filters.ChoiceFilter(choices=Webhook.EVENT_CHOICES)
    date_from = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    date_to = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    webhook_name = filters.CharFilter(field_name='webhook__name', lookup_expr='icontains')
    
    class Meta:
        model = WebhookDelivery
        fields = ['webhook', 'status', 'event_type', 'date_from', 'date_to', 'webhook_name']

class WebhookTestSerializer(serializers.Serializer):
    """Serializer for testing webhook endpoints"""
    
    event_type = serializers.ChoiceField(
        choices=Webhook.EVENT_CHOICES,
        default='user.registered',
        help_text="Type of event to simulate"
    )
    test_data = serializers.JSONField(
        required=False,
        default=dict,
        help_text="Custom test data (optional)"
    )

class WebhookStatsSerializer(serializers.Serializer):
    """Serializer for webhook statistics"""
    
    total_webhooks = serializers.IntegerField()
    active_webhooks = serializers.IntegerField()
    total_deliveries = serializers.IntegerField()
    successful_deliveries = serializers.IntegerField()
    failed_deliveries = serializers.IntegerField()
    pending_deliveries = serializers.IntegerField()
    overall_success_rate = serializers.FloatField()
    deliveries_by_event = serializers.DictField()
    deliveries_by_status = serializers.DictField()
    avg_delivery_time_ms = serializers.IntegerField()
