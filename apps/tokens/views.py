import jwt
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import TokenScope, ScopedToken, TokenIntrospection, TokenRevocation
from .serializers import (
    TokenScopeSerializer, ScopedTokenSerializer, TokenCreateSerializer,
    TokenIntrospectionSerializer, TokenRevocationSerializer, TokenIntrospectionRequestSerializer
)


class TokenScopeViewSet(viewsets.ReadOnlyModelViewSet):
    """View available token scopes"""
    queryset = TokenScope.objects.all()
    serializer_class = TokenScopeSerializer
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def my_scopes(self, request):
        """Get scopes available to current user based on their roles"""
        user = request.user
        
        # Get user's roles and permissions
        from apps.roles.models import UserRole, RolePermission
        
        user_roles = UserRole.objects.filter(
            user=user,
            tenant=request.tenant,
            is_active=True
        ).select_related('role')
        
        # Get permissions from roles
        role_permissions = RolePermission.objects.filter(
            role__in=[ur.role for ur in user_roles],
            tenant=request.tenant
        ).select_related('permission')
        
        permission_codes = [rp.permission.codename for rp in role_permissions]
        
        # Filter scopes based on permissions
        available_scopes = []
        for scope in TokenScope.objects.all():
            scope_required_perms = [f"{scope.resource_type}.{action}" for action in scope.actions]
            if any(perm in permission_codes for perm in scope_required_perms):
                available_scopes.append(scope)
        
        serializer = TokenScopeSerializer(available_scopes, many=True)
        return Response(serializer.data)


class ScopedTokenViewSet(viewsets.ModelViewSet):
    """Manage scoped tokens"""
    serializer_class = ScopedTokenSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'delete']
    
    def get_queryset(self):
        return ScopedToken.objects.filter(
            user=self.request.user,
            tenant=self.request.tenant
        ).prefetch_related('scopes')
    
    def get_serializer_class(self):
        if self.action == 'create':
            return TokenCreateSerializer
        return ScopedTokenSerializer
    
    @method_decorator(ratelimit(key='user', rate='10/h', method='POST', block=True))
    def create(self, request, *args, **kwargs):
        """Create a new scoped token"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Check if user can request the scopes
        requested_scopes = serializer.validated_data['scopes']
        if not self.can_request_scopes(request.user, requested_scopes):
            return Response(
                {'error': 'Insufficient permissions for requested scopes'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        token = serializer.save()
        
        # Log token creation
        from apps.audit.models import AuditLog
        AuditLog.create_log(
            action='token_created',
            user=request.user,
            details={
                'token_id': str(token.id),
                'jti': token.jti,
                'scopes': token.get_scope_names(),
                'audience': token.audience,
                'expires_at': token.expires_at.isoformat()
            },
            risk_level='medium'
        )
        
        return Response(
            ScopedTokenSerializer(token, context={'request': request}).data,
            status=status.HTTP_201_CREATED
        )
    
    def can_request_scopes(self, user, scope_names):
        """Check if user can request the given scopes"""
        from apps.roles.models import UserRole, RolePermission
        
        # Get user's permissions
        user_roles = UserRole.objects.filter(
            user=user,
            tenant=self.request.tenant,
            is_active=True
        ).select_related('role')
        
        role_permissions = RolePermission.objects.filter(
            role__in=[ur.role for ur in user_roles],
            tenant=self.request.tenant
        ).select_related('permission')
        
        permission_codes = set(rp.permission.codename for rp in role_permissions)
        
        # Check each requested scope
        for scope_name in scope_names:
            try:
                scope = TokenScope.objects.get(name=scope_name)
                scope_required_perms = [f"{scope.resource_type}.{action}" for action in scope.actions]
                if not any(perm in permission_codes for perm in scope_required_perms):
                    return False
            except TokenScope.DoesNotExist:
                return False
        
        return True
    
    def destroy(self, request, *args, **kwargs):
        """Revoke a token"""
        token = self.get_object()
        
        # Create revocation record
        TokenRevocation.objects.create(
            token=token,
            revoked_by=request.user,
            reason='user_request',
            notes='Revoked by user via API',
            ip_address=self.get_client_ip(request)
        )
        
        # Revoke the token
        token.revoke(revoked_by=request.user, reason='User requested revocation')
        
        # Log revocation
        from apps.audit.models import AuditLog
        AuditLog.create_log(
            action='token_revoked',
            user=request.user,
            details={
                'token_id': str(token.id),
                'jti': token.jti,
                'reason': 'user_request'
            },
            risk_level='low'
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    
    @action(detail=False, methods=['post'])
    def introspect(self, request):
        """Introspect a token to check its validity and claims"""
        serializer = TokenIntrospectionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token_string = serializer.validated_data['token']
        
        try:
            # Decode the JWT token
            payload = jwt.decode(
                token_string,
                settings.SECRET_KEY,
                algorithms=['HS256'],
                options={'verify_exp': False}  # We'll check expiration manually
            )
            
            jti = payload.get('jti')
            if not jti:
                raise jwt.InvalidTokenError("Missing JTI claim")
            
            # Look up token in database
            try:
                token = ScopedToken.objects.get(jti=jti)
            except ScopedToken.DoesNotExist:
                # Token not found in database
                response_data = {'active': False}
                self.log_introspection(None, request, False, "Token not found in database")
                return Response(TokenIntrospectionSerializer(response_data).data)
            
            # Check if token is valid
            is_valid = token.is_valid()
            validation_reason = "Token is valid" if is_valid else "Token is invalid or expired"
            
            if is_valid:
                # Record token usage
                token.record_usage(self.get_client_ip(request))
                
                # Return token claims
                response_data = {
                    'active': True,
                    'jti': payload.get('jti'),
                    'sub': payload.get('sub'),
                    'aud': payload.get('aud'),
                    'iat': payload.get('iat'),
                    'exp': payload.get('exp'),
                    'nbf': payload.get('nbf'),
                    'tenant_id': payload.get('tenant_id'),
                    'token_type': payload.get('token_type'),
                    'scopes': payload.get('scopes', []),
                    'permissions': payload.get('permissions', []),
                    'usage_count': token.usage_count,
                    'client_id': payload.get('client_id'),
                    'delegated_by': payload.get('delegated_by'),
                    'delegation_chain': payload.get('delegation_chain')
                }
            else:
                response_data = {'active': False}
            
            # Log introspection
            self.log_introspection(token, request, is_valid, validation_reason)
            
            return Response(TokenIntrospectionSerializer(response_data).data)
            
        except jwt.ExpiredSignatureError:
            self.log_introspection(None, request, False, "Token expired")
            return Response(TokenIntrospectionSerializer({'active': False}).data)
        except jwt.InvalidTokenError as e:
            self.log_introspection(None, request, False, f"Invalid token: {str(e)}")
            return Response(TokenIntrospectionSerializer({'active': False}).data)
    
    def log_introspection(self, token, request, was_valid, reason):
        """Log token introspection for audit purposes"""
        if token:
            TokenIntrospection.objects.create(
                token=token,
                requester_ip=self.get_client_ip(request),
                requester_user_agent=request.META.get('HTTP_USER_AGENT', ''),
                was_valid=was_valid,
                validation_reason=reason,
                endpoint=request.path
            )
    
    @action(detail=False, methods=['post'])
    def revoke_all(self, request):
        """Revoke all active tokens for the current user"""
        tokens = ScopedToken.objects.filter(
            user=request.user,
            tenant=request.tenant,
            is_active=True
        )
        
        revoked_count = 0
        for token in tokens:
            TokenRevocation.objects.create(
                token=token,
                revoked_by=request.user,
                reason='user_request',
                notes='Bulk revocation by user',
                ip_address=self.get_client_ip(request)
            )
            token.revoke(revoked_by=request.user, reason='Bulk revocation')
            revoked_count += 1
        
        # Log bulk revocation
        from apps.audit.models import AuditLog
        AuditLog.create_log(
            action='tokens_bulk_revoked',
            user=request.user,
            details={
                'revoked_count': revoked_count,
                'tenant_id': str(request.tenant.id)
            },
            risk_level='medium'
        )
        
        return Response({
            'message': f'Revoked {revoked_count} tokens',
            'revoked_count': revoked_count
        })
    
    @action(detail=False, methods=['get'])
    def usage_stats(self, request):
        """Get token usage statistics for current user"""
        tokens = self.get_queryset()
        
        total_tokens = tokens.count()
        active_tokens = tokens.filter(is_active=True).count()
        expired_tokens = tokens.filter(expires_at__lt=timezone.now()).count()
        revoked_tokens = tokens.filter(is_active=False, revoked_at__isnull=False).count()
        
        # Usage stats
        total_usage = sum(token.usage_count for token in tokens)
        
        # Most used scopes
        scope_usage = {}
        for token in tokens.prefetch_related('scopes'):
            for scope in token.scopes.all():
                scope_usage[scope.name] = scope_usage.get(scope.name, 0) + token.usage_count
        
        return Response({
            'summary': {
                'total_tokens': total_tokens,
                'active_tokens': active_tokens,
                'expired_tokens': expired_tokens,
                'revoked_tokens': revoked_tokens,
                'total_usage': total_usage
            },
            'scope_usage': scope_usage,
            'recent_tokens': ScopedTokenSerializer(
                tokens.order_by('-issued_at')[:5], 
                many=True,
                context={'request': request}
            ).data
        })


class TokenRevocationViewSet(viewsets.ReadOnlyModelViewSet):
    """View token revocation history"""
    serializer_class = TokenRevocationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return TokenRevocation.objects.filter(
            token__user=self.request.user,
            token__tenant=self.request.tenant
        ).select_related('token', 'revoked_by')