from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiParameter
from django.contrib.auth import authenticate
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.http import HttpResponseTooManyRequests
from django.core.exceptions import PermissionDenied
from .serializers import (
    RegistrationSerializer, LoginSerializer, MFAEnableSerializer,
    MFAVerifySerializer, MFADisableSerializer, ForgotPasswordSerializer,
    ResetPasswordSerializer, ActivateAccountSerializer, TokenSerializer,
    RefreshTokenSerializer, EmailVerificationSerializer, VerifyEmailSerializer,
    UserSessionSerializer
)
from .tasks import send_activation_email

class RateLimitedView:
    """Mixin to handle rate limiting with proper error responses"""
    
    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            response = HttpResponseTooManyRequests(
                '{"error": "Rate limit exceeded", "detail": "Too many requests. Please try again later."}',
                content_type='application/json'
            )
            response['Retry-After'] = '60'  # Suggest retry after 60 seconds
            return response

class AuthViewSet(RateLimitedView, viewsets.GenericViewSet):
    """Authentication endpoints"""
    permission_classes = [AllowAny]
    
    def get_serializer_class(self):
        action_serializers = {
            'register': RegistrationSerializer,
            'login': LoginSerializer,
            'refresh': RefreshTokenSerializer,
            'forgot_password': ForgotPasswordSerializer,
            'reset_password': ResetPasswordSerializer,
            'activate': ActivateAccountSerializer,
            'send_verification': EmailVerificationSerializer,
            'verify_email': VerifyEmailSerializer,
        }
        return action_serializers.get(self.action, RegistrationSerializer)
    
    @extend_schema(
        summary="User Registration",
        description="Register a new user account. Account will be inactive until email verification.",
        responses={201: TokenSerializer}
    )
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    @action(detail=False, methods=['post'])
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Send activation email
            tenant = request.tenant
            send_activation_email.delay(
                user.id,
                user.email,
                tenant.domain_url
            )
            
            # Also send verification email for email verification
            from .tasks import send_verification_email
            send_verification_email.delay(
                user.id,
                user.email,
                tenant.domain_url
            )
            
            return Response({
                'message': 'Registration successful. Please check your email to activate your account.',
                'user_id': str(user.id)
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="User Login",
        description="Authenticate user and return JWT tokens. MFA token required if enabled.",
        responses={200: TokenSerializer}
    )
    @method_decorator(ratelimit(key='ip', rate='10/m', method='POST', block=True))
    @action(detail=False, methods=['post'])
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token
            
            return Response({
                'access': str(access),
                'refresh': str(refresh),
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'mfa_enabled': user.mfa_enabled,
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Refresh JWT Token",
        description="Get a new access token using refresh token",
        responses={200: TokenSerializer}
    )
    @action(detail=False, methods=['post'])
    def refresh(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            return Response({
                'access': serializer.validated_data['access']
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Forgot Password",
        description="Send password reset email if user exists",
    )
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    @action(detail=False, methods=['post'])
    def forgot_password(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Reset Password",
        description="Reset password using token from email",
        parameters=[
            OpenApiParameter('uid', str, location=OpenApiParameter.PATH),
            OpenApiParameter('token', str, location=OpenApiParameter.PATH),
        ]
    )
    @action(detail=False, methods=['post'], url_path='reset-password/(?P<uid>[^/.]+)/(?P<token>[^/.]+)')
    def reset_password(self, request, uid=None, token=None):
        data = request.data.copy()
        data['uid'] = uid
        data['token'] = token
        
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Activate Account",
        description="Activate user account using token from email",
        parameters=[
            OpenApiParameter('uid', str, location=OpenApiParameter.PATH),
            OpenApiParameter('token', str, location=OpenApiParameter.PATH),
        ]
    )
    @action(detail=False, methods=['get'], url_path='activate/(?P<uid>[^/.]+)/(?P<token>[^/.]+)')
    def activate(self, request, uid=None, token=None):
        data = {'uid': uid, 'token': token}
        
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Send Email Verification",
        description="Send email verification link to user's email address",
    )
    @method_decorator(ratelimit(key='ip', rate='3/m', method='POST', block=True))
    @action(detail=False, methods=['post'], url_path='send-verification')
    def send_verification(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Verify Email",
        description="Verify user's email address using token from verification email",
        parameters=[
            OpenApiParameter('uid', str, location=OpenApiParameter.PATH),
            OpenApiParameter('token', str, location=OpenApiParameter.PATH),
        ]
    )
    @action(detail=False, methods=['get'], url_path='verify-email/(?P<uid>[^/.]+)/(?P<token>[^/.]+)')
    def verify_email(self, request, uid=None, token=None):
        data = {'uid': uid, 'token': token}
        
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MFAViewSet(viewsets.GenericViewSet):
    """Multi-Factor Authentication endpoints"""
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        action_serializers = {
            'enable': MFAEnableSerializer,
            'verify': MFAVerifySerializer,
            'disable': MFADisableSerializer,
        }
        return action_serializers.get(self.action, MFAEnableSerializer)
    
    @extend_schema(
        summary="Enable MFA",
        description="Enable Multi-Factor Authentication and get QR code for TOTP setup",
    )
    @action(detail=False, methods=['post'])
    def enable(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Verify MFA Token",
        description="Verify TOTP token to complete MFA setup or authenticate",
    )
    @action(detail=False, methods=['post'])
    def verify(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Disable MFA",
        description="Disable Multi-Factor Authentication (requires password confirmation)",
    )
    @action(detail=False, methods=['post'])
    def disable(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="MFA Status",
        description="Get current MFA status for the authenticated user",
    )
    @action(detail=False, methods=['get'])
    def status(self, request):
        user = request.user
        return Response({
            'mfa_enabled': user.mfa_enabled,
            'devices': user.totpdevice_set.filter(confirmed=True).count()
        }, status=status.HTTP_200_OK)

class LogoutView(APIView):
    """Logout endpoint"""
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="User Logout",
        description="Logout user by blacklisting the refresh token",
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                
                # Revoke session if exists
                from .models import UserSession
                refresh_jti = token.payload.get('jti')
                UserSession.revoke_by_jti(refresh_jti, reason='logout')
                
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class SessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for managing user sessions
    
    Provides endpoints to:
    - List active sessions
    - View session details
    - Revoke sessions
    """
    
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return sessions for current user"""
        from .models import UserSession
        return UserSession.objects.filter(
            user=self.request.user,
            tenant=self.request.tenant
        )
    
    @extend_schema(
        summary="List Sessions",
        description="Get all active sessions for the current user"
    )
    def list(self, request, *args, **kwargs):
        """List all sessions for current user"""
        return super().list(request, *args, **kwargs)
    
    @extend_schema(
        summary="Get Session Details",
        description="Get details of a specific session"
    )
    def retrieve(self, request, *args, **kwargs):
        """Get specific session details"""
        return super().retrieve(request, *args, **kwargs)
    
    @action(detail=True, methods=['delete'])
    def revoke(self, request, pk=None):
        """
        Revoke a specific session
        
        DELETE /api/auth/sessions/{id}/revoke/
        """
        session = self.get_object()
        
        # Don't allow revoking current session this way
        current_token = request.auth
        if hasattr(current_token, 'payload'):
            current_jti = current_token.payload.get('jti')
            if session.jti == current_jti:
                return Response({
                    'error': 'Cannot revoke current session. Use logout instead.'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        session.revoke(reason='manual_revoke')
        
        # Try to blacklist the tokens
        try:
            refresh_token = RefreshToken()
            refresh_token.payload['jti'] = session.refresh_jti
            refresh_token.blacklist()
        except Exception:
            pass  # Token might already be blacklisted
        
        return Response({
            'message': 'Session revoked successfully',
            'session_id': str(session.id)
        })
    
    @action(detail=False, methods=['delete'])
    def revoke_all(self, request):
        """
        Revoke all other sessions except current
        
        DELETE /api/auth/sessions/revoke-all/
        """
        from .models import UserSession
        
        # Get current session JTI to exclude it
        current_jti = None
        if hasattr(request.auth, 'payload'):
            current_jti = request.auth.payload.get('jti')
        
        # Get all user sessions except current
        sessions_to_revoke = UserSession.objects.filter(
            user=request.user,
            tenant=request.tenant,
            is_active=True
        )
        
        if current_jti:
            sessions_to_revoke = sessions_to_revoke.exclude(jti=current_jti)
        
        # Revoke all sessions
        count = 0
        for session in sessions_to_revoke:
            session.revoke(reason='revoke_all')
            
            # Try to blacklist refresh tokens
            try:
                refresh_token = RefreshToken()
                refresh_token.payload['jti'] = session.refresh_jti
                refresh_token.blacklist()
            except Exception:
                pass
            
            count += 1
        
        return Response({
            'message': f'Revoked {count} sessions successfully',
            'revoked_count': count
        })
    
    @action(detail=False, methods=['get'])
    def current(self, request):
        """
        Get current session information
        
        GET /api/auth/sessions/current/
        """
        from .models import UserSession
        
        if not hasattr(request.auth, 'payload'):
            return Response({
                'error': 'No valid token found'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        current_jti = request.auth.payload.get('jti')
        if not current_jti:
            return Response({
                'error': 'No JTI in token'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session = UserSession.objects.get(
                jti=current_jti,
                user=request.user,
                tenant=request.tenant,
                is_active=True
            )
            
            # Update last used timestamp
            session.update_last_used()
            
            serializer = self.get_serializer(session, context={'request': request})
            return Response(serializer.data)
            
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)