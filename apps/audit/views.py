from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import AuditLog
from .serializers import AuditLogSerializer, AuditLogFilterSet, AuditStatsSerializer

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for audit logs with filtering and statistics
    
    Provides endpoints for:
    - Listing audit logs with filtering
    - Retrieving specific audit log entries
    - Statistics and analytics
    """
    
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = AuditLogFilterSet
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """Filter audit logs to current tenant and apply permissions"""
        queryset = super().get_queryset().filter(tenant=self.request.tenant)
        
        # Only allow users with audit.view_all permission to see all logs
        if not self.request.user.has_perm('audit.view_all', self.request.tenant):
            # Regular users can only see their own audit logs
            queryset = queryset.filter(actor=self.request.user)
        
        return queryset.select_related('actor', 'tenant')
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get audit log statistics for the current tenant
        
        Query parameters:
        - days: Number of days to look back (default: 30)
        """
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        
        queryset = self.get_queryset().filter(timestamp__gte=since)
        
        # Basic stats
        total_events = queryset.count()
        failed_events = queryset.filter(success=False).count()
        unique_users = queryset.exclude(actor__isnull=True).values('actor').distinct().count()
        unique_ips = queryset.exclude(ip_address__isnull=True).values('ip_address').distinct().count()
        
        # Events by action
        events_by_action = dict(
            queryset.values('action').annotate(
                count=Count('id')
            ).values_list('action', 'count')
        )
        
        # Events by risk level
        events_by_risk_level = dict(
            queryset.values('risk_level').annotate(
                count=Count('id')
            ).values_list('risk_level', 'count')
        )
        
        stats_data = {
            'total_events': total_events,
            'failed_events': failed_events,
            'unique_users': unique_users,
            'unique_ips': unique_ips,
            'events_by_action': events_by_action,
            'events_by_risk_level': events_by_risk_level,
            'date_range': {
                'from': since.isoformat(),
                'to': timezone.now().isoformat(),
                'days': days
            }
        }
        
        serializer = AuditStatsSerializer(stats_data)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def security_events(self, request):
        """
        Get high-risk security events
        
        Returns events with risk_level='high' or 'critical', or failed login attempts
        """
        queryset = self.get_queryset().filter(
            Q(risk_level__in=['high', 'critical']) |
            Q(action='login_failed') |
            Q(success=False)
        )
        
        # Optional time filtering
        days = int(request.query_params.get('days', 7))
        since = timezone.now() - timedelta(days=days)
        queryset = queryset.filter(timestamp__gte=since)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def user_activity(self, request):
        """
        Get activity for a specific user
        
        Query parameters:
        - user_id: UUID of user to get activity for
        - email: Email of user to get activity for
        - days: Number of days to look back (default: 7)
        """
        user_id = request.query_params.get('user_id')
        email = request.query_params.get('email')
        days = int(request.query_params.get('days', 7))
        
        if not user_id and not email:
            return Response({
                'error': 'Either user_id or email parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        since = timezone.now() - timedelta(days=days)
        queryset = self.get_queryset().filter(timestamp__gte=since)
        
        if user_id:
            queryset = queryset.filter(actor_id=user_id)
        elif email:
            queryset = queryset.filter(actor_email__iexact=email)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def failed_logins(self, request):
        """
        Get failed login attempts
        
        Query parameters:
        - ip: Filter by IP address
        - days: Number of days to look back (default: 7)
        """
        days = int(request.query_params.get('days', 7))
        since = timezone.now() - timedelta(days=days)
        
        queryset = self.get_queryset().filter(
            action='login_failed',
            timestamp__gte=since
        )
        
        # Optional IP filtering
        ip = request.query_params.get('ip')
        if ip:
            queryset = queryset.filter(ip_address=ip)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


