from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.http import HttpResponseTooManyRequests
from django_tenants.utils import schema_context
from .models import *
from .serializers import *

class TenantViewSet(viewsets.ModelViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    
    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            response = HttpResponseTooManyRequests(
                '{"error": "Rate limit exceeded", "detail": "Too many requests. Please try again later."}',
                content_type='application/json'
            )
            response['Retry-After'] = '300'  # 5 minutes for tenant creation
            return response
    
    def get_permissions(self):
        """Allow public access to tenant creation, require auth for everything else"""
        if self.action == 'create_tenant':
            return [AllowAny()]
        return [IsAuthenticated()]

    def get_queryset(self):
        if hasattr(self.request, 'tenant') and self.request.tenant:
            return super().get_queryset().filter(schema_name=self.request.tenant.schema_name)
        return super().get_queryset()

    @method_decorator(csrf_exempt)
    @method_decorator(ratelimit(key='ip', rate='3/h', method='POST', block=True))
    @action(detail=False, methods=['post'], url_path='create', permission_classes=[AllowAny])
    def create_tenant(self, request):
        """
        Create a new tenant with domain, admin user, and default roles/permissions.
        
        POST /api/tenants/create/
        {
            "name": "Acme Corp",
            "description": "Acme Corporation",
            "domain": "acme.authly.com",
            "contact_email": "contact@acme.com",
            "contact_phone": "+1-555-0123",
            "plan": "enterprise",
            "admin_email": "admin@acme.com",
            "admin_password": "SecurePassword123!",
            "admin_first_name": "John",
            "admin_last_name": "Doe"
        }
        
        Returns tenant details with admin JWT tokens.
        """
        serializer = TenantCreationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': 'Validation failed',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Create tenant, domain, admin user, roles, and permissions
            result = serializer.save()
            tenant = result['tenant']
            domain = result['domain']
            admin_user = result['admin_user']
            
            # Generate JWT tokens for admin user
            with schema_context(tenant.schema_name):
                refresh = RefreshToken.for_user(admin_user)
                access_token = refresh.access_token
                
                # Add custom claims
                access_token['tenant_id'] = str(tenant.id)
                access_token['tenant_slug'] = tenant.slug
                access_token['is_admin'] = True
                
                refresh['tenant_id'] = str(tenant.id)
                refresh['tenant_slug'] = tenant.slug
            
            # Prepare response
            response_serializer = TenantCreationResponseSerializer({
                'tenant': tenant,
                'domain': domain,
                'admin_token': str(access_token),
                'admin_refresh_token': str(refresh)
            })
            
            return Response({
                'success': True,
                'message': 'Tenant created successfully',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': 'Tenant creation failed',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='info')
    def tenant_info(self, request):
        """Get current tenant information"""
        if not hasattr(request, 'tenant') or not request.tenant:
            return Response({
                'error': 'No tenant context'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = TenantSerializer(request.tenant)
        return Response({
            'success': True,
            'data': serializer.data
        })


