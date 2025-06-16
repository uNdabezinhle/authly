# users/views/auth_views.py

from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import get_object_or_404

from users.models import User, TwoFactorDevice, RefreshToken
from users.serializers import (
    LoginSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    TwoFactorEnableSerializer,
    TwoFactorConfirmSerializer,
    TwoFactorDisableSerializer,
    TwoFactorVerifySerializer,
    RefreshTokenSerializer,
    LogoutSerializer
)

class AuthRateThrottle(AnonRateThrottle):
    """
    Rate throttle specifically for authentication endpoints.
    """
    scope = 'auth'

class LoginView(GenericAPIView):
    """
    View for user login.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer
    throttle_classes = [AuthRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TwoFactorVerifyView(GenericAPIView):
    """
    View for verifying two-factor authentication code during login.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = TwoFactorVerifySerializer
    throttle_classes = [AuthRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TwoFactorEnableView(GenericAPIView):
    """
    View for enabling two-factor authentication.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TwoFactorEnableSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        
        response_data = {
            'secret': result['secret'],
            'provisioning_uri': result['provisioning_uri'],
            'device_id': str(result['device'].id)
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)

class TwoFactorConfirmView(GenericAPIView):
    """
    View for confirming two-factor authentication setup.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TwoFactorConfirmSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        return Response({
            'detail': _('Two-factor authentication has been enabled.'),
            'two_factor_enabled': True
        }, status=status.HTTP_200_OK)

class TwoFactorDisableView(GenericAPIView):
    """
    View for disabling two-factor authentication.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TwoFactorDisableSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        return Response({
            'detail': _('Two-factor authentication has been disabled.'),
            'two_factor_enabled': False
        }, status=status.HTTP_200_OK)

class PasswordChangeView(GenericAPIView):
    """
    View for changing user password.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PasswordChangeSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Revoke all refresh tokens to force re-login with new password
        RefreshToken.objects.filter(user=request.user, revoked_at=None).update(revoked_at=timezone.now())
        
        return Response({
            'detail': _('Password has been changed successfully. Please log in again with your new password.')
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    """
    View for requesting a password reset.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer
    throttle_classes = [AuthRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        # Do not reveal if the user exists
        try:
            user = User.objects.get(email=email)
            
            # Generate reset token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            # Create password reset URL
            reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
            
            # Prepare email
            context = {
                'user': user,
                'reset_url': reset_url,
                'valid_hours': 24  # Token validity in hours
            }
            
            # Email subject and message
            subject = _('Password Reset Request')
            message = render_to_string('email/password_reset.txt', context)
            html_message = render_to_string('email/password_reset.html', context)
            
            # Send email
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
                fail_silently=False
            )
        except User.DoesNotExist:
            # Do not reveal that the user does not exist
            pass
        
        return Response({
            'detail': _('If an account with this email exists, a password reset link has been sent.')
        }, status=status.HTTP_200_OK)

class PasswordResetConfirmView(GenericAPIView):
    """
    View for confirming a password reset.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer
    throttle_classes = [AuthRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Extract data
        validated_data = serializer.validated_data
        token_data = validated_data['token'].split('/')
        
        if len(token_data) != 2:
            return Response({
                'detail': _('Invalid token format.')
            }, status=status.HTTP_400_BAD_REQUEST)
        
        uid, token = token_data
        
        try:
            # Decode the user ID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
            
            # Check if the token is valid
            if not default_token_generator.check_token(user, token):
                return Response({
                    'detail': _('Invalid or expired token.')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Set the new password
            password = validated_data['password']
            user.set_password(password)
            
            # Update password change information
            user.password_changed_at = timezone.now()
            user.set_password_expiry()
            
            # Save the user
            user.save()
            
            # Add password to history
            user.add_to_password_history(user.password)
            
            # Revoke all refresh tokens
            RefreshToken.objects.filter(user=user, revoked_at=None).update(revoked_at=timezone.now())
            
            return Response({
                'detail': _('Password has been reset successfully. You can now log in with your new password.')
            }, status=status.HTTP_200_OK)
            
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({
                'detail': _('Invalid token.')
            }, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(GenericAPIView):
    """
    View for refreshing access tokens.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = RefreshTokenSerializer
    throttle_classes = [AuthRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LogoutView(GenericAPIView):
    """
    View for logging out and revoking refresh tokens.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_200_OK)

class SessionView(APIView):
    """
    View for checking the validity of the current session.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        from users.serializers import UserSerializer
        return Response({
            'is_authenticated': True,
            'user': UserSerializer(request.user).data
        }, status=status.HTTP_200_OK)