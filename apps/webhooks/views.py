from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta
import uuid
from .models import Webhook, WebhookDelivery, WebhookEvent
from .serializers import (
    WebhookSerializer, WebhookCreateSerializer, WebhookDeliverySerializer,
    WebhookDeliveryFilterSet, WebhookTestSerializer, WebhookStatsSerializer
)
from .tasks import deliver_webhook

class WebhookViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing webhooks
    
    Provides CRUD operations for webhook configuration plus:
    - Testing webhook endpoints
    - Viewing delivery statistics
    - Managing webhook events
    """
    
    queryset = Webhook.objects.all()
    serializer_class = WebhookSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter webhooks to current tenant"""
        return super().get_queryset().filter(tenant=self.request.tenant)
    
    def get_serializer_class(self):
        """Use different serializer for creation to include secret"""
        if self.action == 'create':
            return WebhookCreateSerializer
        return super().get_serializer_class()
    
    def perform_create(self, serializer):
        """Set tenant and creator when creating webhook"""
        serializer.save(
            tenant=self.request.tenant,
            created_by=self.request.user
        )
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Test a webhook by sending a test event
        
        POST /api/webhooks/{id}/test/
        {
            "event_type": "user.registered",
            "test_data": {"test": true}
        }
        """
        webhook = self.get_object()
        serializer = WebhookTestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        event_type = serializer.validated_data['event_type']
        test_data = serializer.validated_data.get('test_data', {})
        
        # Check if webhook is subscribed to this event
        if not webhook.is_event_subscribed(event_type):
            return Response({
                'error': f'Webhook is not subscribed to event: {event_type}',
                'subscribed_events': webhook.events
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create test payload
        test_payload = {
            'test': True,
            'timestamp': timezone.now().isoformat(),
            'user': {
                'id': str(request.user.id),
                'email': request.user.email,
                'name': f"{request.user.first_name} {request.user.last_name}".strip()
            },
            **test_data
        }
        
        # Create delivery record
        delivery = WebhookDelivery.objects.create(
            webhook=webhook,
            tenant=request.tenant,
            event_type=event_type,
            event_id=uuid.uuid4(),
            payload=test_payload,
            max_attempts=1  # Only try once for tests
        )
        
        # Trigger immediate delivery
        deliver_webhook.delay(delivery.id)
        
        return Response({
            'success': True,
            'message': 'Test webhook queued for delivery',
            'delivery_id': delivery.id,
            'event_type': event_type
        })
    
    @action(detail=True, methods=['get'])
    def deliveries(self, request, pk=None):
        """
        Get delivery history for a specific webhook
        
        GET /api/webhooks/{id}/deliveries/
        """
        webhook = self.get_object()
        queryset = webhook.deliveries.all()
        
        # Apply date filtering
        days = int(request.query_params.get('days', 7))
        since = timezone.now() - timedelta(days=days)
        queryset = queryset.filter(created_at__gte=since)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebhookDeliverySerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = WebhookDeliverySerializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        """
        Get statistics for a specific webhook
        
        GET /api/webhooks/{id}/stats/
        """
        webhook = self.get_object()
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        
        deliveries = webhook.deliveries.filter(created_at__gte=since)
        
        stats = {
            'total_deliveries': deliveries.count(),
            'successful_deliveries': deliveries.filter(status='success').count(),
            'failed_deliveries': deliveries.filter(status__in=['failed', 'abandoned']).count(),
            'pending_deliveries': deliveries.filter(status__in=['pending', 'retrying']).count(),
            'avg_delivery_time': deliveries.filter(
                attempted_at__isnull=False,
                completed_at__isnull=False
            ).aggregate(
                avg_time=Avg(
                    timezone.now() - timezone.F('attempted_at')
                )
            )['avg_time'],
            'deliveries_by_event': dict(
                deliveries.values('event_type').annotate(
                    count=Count('id')
                ).values_list('event_type', 'count')
            ),
            'deliveries_by_status': dict(
                deliveries.values('status').annotate(
                    count=Count('id')
                ).values_list('status', 'count')
            ),
            'date_range': {
                'from': since.isoformat(),
                'to': timezone.now().isoformat(),
                'days': days
            }
        }
        
        return Response(stats)
    
    @action(detail=False, methods=['get'])
    def events(self, request):
        """
        Get list of supported webhook events
        
        GET /api/webhooks/events/
        """
        return Response({
            'supported_events': [
                {
                    'type': choice[0],
                    'name': choice[1]
                }
                for choice in Webhook.EVENT_CHOICES
            ]
        })

class WebhookDeliveryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for webhook delivery records
    
    Provides endpoints for viewing delivery history and statistics
    """
    
    queryset = WebhookDelivery.objects.all()
    serializer_class = WebhookDeliverySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = WebhookDeliveryFilterSet
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter deliveries to current tenant"""
        return super().get_queryset().filter(
            tenant=self.request.tenant
        ).select_related('webhook', 'tenant')
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get overall webhook delivery statistics
        
        GET /api/webhook-deliveries/stats/
        """
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        
        # Get webhooks and deliveries for tenant
        webhooks = Webhook.objects.filter(tenant=request.tenant)
        deliveries = self.get_queryset().filter(created_at__gte=since)
        
        # Calculate delivery time average (in milliseconds)
        avg_delivery_time = deliveries.filter(
            attempted_at__isnull=False,
            completed_at__isnull=False
        ).aggregate(
            avg_seconds=Avg(
                timezone.F('completed_at') - timezone.F('attempted_at')
            )
        )['avg_seconds']
        
        avg_delivery_time_ms = int(avg_delivery_time.total_seconds() * 1000) if avg_delivery_time else 0
        
        # Basic stats
        total_deliveries = deliveries.count()
        successful_deliveries = deliveries.filter(status='success').count()
        failed_deliveries = deliveries.filter(status__in=['failed', 'abandoned']).count()
        
        stats_data = {
            'total_webhooks': webhooks.count(),
            'active_webhooks': webhooks.filter(is_active=True).count(),
            'total_deliveries': total_deliveries,
            'successful_deliveries': successful_deliveries,
            'failed_deliveries': failed_deliveries,
            'pending_deliveries': deliveries.filter(status__in=['pending', 'retrying']).count(),
            'overall_success_rate': round(
                (successful_deliveries / total_deliveries * 100) if total_deliveries > 0 else 0,
                2
            ),
            'deliveries_by_event': dict(
                deliveries.values('event_type').annotate(
                    count=Count('id')
                ).values_list('event_type', 'count')
            ),
            'deliveries_by_status': dict(
                deliveries.values('status').annotate(
                    count=Count('id')
                ).values_list('status', 'count')
            ),
            'avg_delivery_time_ms': avg_delivery_time_ms
        }
        
        serializer = WebhookStatsSerializer(stats_data)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """
        Retry a failed webhook delivery
        
        POST /api/webhook-deliveries/{id}/retry/
        """
        delivery = self.get_object()
        
        if not delivery.can_retry():
            return Response({
                'error': 'Delivery cannot be retried',
                'reason': f'Status: {delivery.status}, Attempts: {delivery.attempt_count}/{delivery.max_attempts}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not delivery.webhook.is_active:
            return Response({
                'error': 'Cannot retry delivery for inactive webhook'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Reset delivery for retry
        delivery.status = 'pending'
        delivery.error_message = ''
        delivery.next_retry_at = None
        delivery.save()
        
        # Queue for immediate delivery
        deliver_webhook.delay(delivery.id)
        
        return Response({
            'success': True,
            'message': 'Delivery queued for retry',
            'delivery_id': str(delivery.id)
        })


