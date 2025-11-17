from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.password_validation import validate_password
from django_otp.models import Device
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.tokens import RefreshToken
from apps.users.models import User
from .models import UserSession
import qrcode
import io
import base64

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password_confirm']
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
        
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(
            **validated_data,
            is_active=False  # Require email activation
        )
        user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    mfa_token = serializers.CharField(required=False)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        mfa_token = attrs.get('mfa_token')
        
        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            if not user.is_active:
                raise serializers.ValidationError('Account is not activated')
            
            # Check email verification
            if not user.email_verified:
                raise serializers.ValidationError('Email address is not verified. Please check your email for verification link.')
                
            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_token:
                    raise serializers.ValidationError('MFA token required')
                    
                # Verify TOTP token
                device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
                if not device or not device.verify_token(mfa_token):
                    raise serializers.ValidationError('Invalid MFA token')
                    
            attrs['user'] = user
        return attrs

class MFAEnableSerializer(serializers.Serializer):
    device_name = serializers.CharField(max_length=64, default='Authly TOTP')
    
    def validate(self, attrs):
        user = self.context['request'].user
        if user.mfa_enabled:
            raise serializers.ValidationError('MFA is already enabled')
        return attrs
        
    def save(self):
        user = self.context['request'].user
        device_name = self.validated_data['device_name']
        
        # Create TOTP device
        device = TOTPDevice.objects.create(
            user=user,
            name=device_name,
            confirmed=False
        )
        
        # Generate QR code
        qr_url = device.config_url
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_image = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': device.bin_key,
            'qr_code': f'data:image/png;base64,{qr_code_image}',
            'backup_tokens': [],  # Can implement backup tokens later
            'device_id': device.id
        }

class MFAVerifySerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6, min_length=6)
    device_id = serializers.IntegerField(required=False)
    
    def validate(self, attrs):
        user = self.context['request'].user
        token = attrs['token']
        device_id = attrs.get('device_id')
        
        if device_id:
            # Verifying during setup
            try:
                device = TOTPDevice.objects.get(id=device_id, user=user, confirmed=False)
            except TOTPDevice.DoesNotExist:
                raise serializers.ValidationError('Invalid device')
        else:
            # Verifying existing device
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if not device:
                raise serializers.ValidationError('No MFA device found')
                
        if not device.verify_token(token):
            raise serializers.ValidationError('Invalid token')
            
        attrs['device'] = device
        return attrs
        
    def save(self):
        device = self.validated_data['device']
        user = self.context['request'].user
        
        if not device.confirmed:
            # Enable MFA
            device.confirmed = True
            device.save()
            user.mfa_enabled = True
            user.save()
            return {'message': 'MFA enabled successfully'}
        else:
            # Just verification
            return {'message': 'Token verified'}

class MFADisableSerializer(serializers.Serializer):
    password = serializers.CharField()
    
    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Invalid password')
        return value
        
    def save(self):
        user = self.context['request'].user
        
        # Delete all TOTP devices
        TOTPDevice.objects.filter(user=user).delete()
        
        # Disable MFA
        user.mfa_enabled = False
        user.save()
        
        return {'message': 'MFA disabled successfully'}

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            user = User.objects.get(email=value, is_active=True)
            self.user = user
        except User.DoesNotExist:
            # Don't reveal if email exists or not
            pass
        return value
        
    def save(self):
        if hasattr(self, 'user'):
            from .tasks import send_password_reset_email
            tenant = self.context['request'].tenant
            send_password_reset_email.delay(
                self.user.id,
                self.user.email,
                tenant.domain_url
            )
        return {'message': 'If the email exists, a password reset link has been sent'}

class ResetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
            
        # Verify token
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid reset link')
            
        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError('Invalid or expired reset link')
            
        attrs['user'] = user
        return attrs
        
    def save(self):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.save()
        return {'message': 'Password reset successfully'}

class ActivateAccountSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    
    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid activation link')
            
        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError('Invalid or expired activation link')
            
        if user.is_active:
            raise serializers.ValidationError('Account is already activated')
            
        attrs['user'] = user
        return attrs
        
    def save(self):
        user = self.validated_data['user']
        user.is_active = True
        user.save()
        return {'message': 'Account activated successfully'}

class TokenSerializer(serializers.Serializer):
    """Serializer for JWT token response"""
    access = serializers.CharField()
    refresh = serializers.CharField()
    
class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    
    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs['refresh'])
            attrs['access'] = str(refresh.access_token)
        except Exception:
            raise serializers.ValidationError('Invalid refresh token')
        return attrs

class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for requesting email verification"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            if user.email_verified:
                raise serializers.ValidationError('Email is already verified')
            self.user = user
        except User.DoesNotExist:
            raise serializers.ValidationError('User with this email does not exist')
        return value
    
    def save(self):
        from .tasks import send_verification_email
        tenant = self.context['request'].tenant
        send_verification_email.delay(
            self.user.id,
            self.user.email,
            tenant.domain_url
        )
        return {'message': 'Verification email sent successfully'}

class VerifyEmailSerializer(serializers.Serializer):
    """Serializer for email verification with token"""
    uid = serializers.CharField()
    token = serializers.CharField()
    
    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid verification link')
            
        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError('Invalid or expired verification link')
            
        if user.email_verified:
            raise serializers.ValidationError('Email is already verified')
            
        attrs['user'] = user
        return attrs
        
    def save(self):
        user = self.validated_data['user']
        user.email_verified = True
        user.save(update_fields=['email_verified'])
        
        # Log the verification event
        from apps.audit.models import AuditLog
        AuditLog.log_action(
            tenant=user.tenant,
            action='activate',
            actor=user,
            resource='user',
            resource_id=user.id,
            resource_name=user.email,
            risk_level='low',
            metadata={'verification_method': 'email_link'}
        )
        
        return {'message': 'Email verified successfully'}

class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user session information"""
    
    is_current = serializers.SerializerMethodField()
    time_since_created = serializers.SerializerMethodField()
    time_since_used = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'device_name', 'ip_address', 'location', 'created_at',
            'last_used_at', 'expires_at', 'is_active', 'revoked_at',
            'revoked_reason', 'is_current', 'time_since_created', 'time_since_used'
        ]
        read_only_fields = '__all__'
    
    def get_is_current(self, obj):
        """Check if this is the current session"""
        request = self.context.get('request')
        if not request or not hasattr(request, 'auth'):
            return False
        
        # Get JTI from current token
        current_token = request.auth
        if hasattr(current_token, 'payload'):
            current_jti = current_token.payload.get('jti')
            return obj.jti == current_jti
        return False
    
    def get_time_since_created(self, obj):
        """Time since session was created (in seconds)"""
        return int((timezone.now() - obj.created_at).total_seconds())
    
    def get_time_since_used(self, obj):
        """Time since session was last used (in seconds)"""
        return int((timezone.now() - obj.last_used_at).total_seconds())

