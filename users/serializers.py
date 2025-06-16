# users/serializers.py

from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from phonenumber_field.serializerfields import PhoneNumberField
from .models import User, TwoFactorDevice, RefreshToken as UserRefreshToken

class UserSerializer(serializers.ModelSerializer):
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'tenant', 'email', 'username', 'first_name', 'last_name',
            'is_active', 'is_staff', 'date_joined'
        ]

class UserCreateSerializer(serializers.ModelSerializer):
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'tenant', 'email', 'username', 'first_name', 'last_name',
            'password'
        ]

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'tenant', 'email', 'username', 'first_name', 'last_name',
            'is_active', 'is_staff'
        ]

class TwoFactorDeviceSerializer(serializers.ModelSerializer):
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = TwoFactorDevice
        fields = [
            'id', 'tenant', 'user', 'name', 'type', 'is_active', 'created_at'
        ]

class RefreshTokenSerializer(serializers.ModelSerializer):
    tenant = serializers.UUIDField(source='tenant.id', read_only=True)

    class Meta:
        model = UserRefreshToken
        fields = [
            'id', 'tenant', 'user', 'token', 'created_at', 'expires_at', 'revoked_at'
        ]

class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing a user's password.
    """
    current_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Current password is incorrect."))
        return value
    
    def validate(self, attrs):
        # Check that new passwords match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": _("New passwords do not match.")})
        
        # Check that new password is different from current
        if attrs['current_password'] == attrs['new_password']:
            raise serializers.ValidationError({"new_password": _("New password must be different from current password.")})
        
        # Check password history
        user = self.context['request'].user
        for pwd_entry in user.password_history or []:
            from django.contrib.auth.hashers import check_password
            if check_password(attrs['new_password'], pwd_entry.get('password')):
                raise serializers.ValidationError({"new_password": _("This password has been used recently. Please choose a different password.")})
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        password = self.validated_data['new_password']
        
        # Set the new password
        user.set_password(password)
        
        # Record password change information
        user.password_changed_at = timezone.now()
        user.set_password_expiry()  # Set password expiry with default policy
        
        # Save the user with updated fields
        user.save()
        
        # Add password to history
        user.add_to_password_history(user.password)
        
        return user

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset.
    """
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        # Check if a user with this email exists
        if not User.objects.filter(email=value).exists():
            # We don't want to reveal if an email exists, so we silently pass
            # but in a real system you might want to log this
            pass
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming a password reset.
    """
    token = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        # Check that passwords match
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": _("Passwords do not match.")})
        
        # Validate token (implementation depends on how you store reset tokens)
        # This would be implemented according to your token storage mechanism
        
        return attrs

class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Try to get the user first to check if account is locked
            try:
                user = User.objects.get(email=email)
                if user.is_locked():
                    raise serializers.ValidationError(_("Account is locked due to too many failed login attempts."))
            except User.DoesNotExist:
                # We'll let authenticate handle the error
                pass
            
            # Authenticate user
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            
            if not user:
                # Record failed login
                try:
                    user = User.objects.get(email=email)
                    user.record_login_failure()
                    
                    # Check if the account is now locked
                    if user.is_locked():
                        # Include lockout information in error
                        lock_minutes = int((user.locked_until - timezone.now()).total_seconds() / 60) + 1
                        raise serializers.ValidationError(
                            _("Account is now locked for {} minutes due to too many failed login attempts.").format(lock_minutes)
                        )
                except User.DoesNotExist:
                    # Don't reveal if email exists
                    pass
                    
                raise serializers.ValidationError(_("Unable to log in with provided credentials."))
                
            # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError(_("User account is disabled."))
            
            # Check if password is expired
            if user.is_password_expired():
                raise serializers.ValidationError(_("Your password has expired. Please reset your password."))
            
            # Record successful login
            user.record_login_success()
            
            # Check if 2FA is required
            if user.two_factor_enabled:
                # Return partial login information with 2FA required flag
                return {
                    'user': user,
                    'requires_2fa': True
                }
        else:
            raise serializers.ValidationError(_("Must include 'email' and 'password'."))
        
        # If we get here, authentication was successful
        return {
            'user': user,
            'requires_2fa': False
        }
    
    def to_representation(self, instance):
        """
        Return tokens if authentication is complete, otherwise return 2FA status.
        """
        if instance.get('requires_2fa'):
            return {
                'requires_2fa': True,
                'user_id': str(instance['user'].id)
            }
        else:
            user = instance['user']
            refresh = RefreshToken.for_user(user)
            
            # Create a refresh token record
            request = self.context.get('request')
            UserRefreshToken.objects.create(
                user=user,
                token=str(refresh),
                expires_at=timezone.now() + timezone.timedelta(days=7),
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT', '') if request else ''
            )
            
            return {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': UserSerializer(user).data
            }

class TwoFactorVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying a two-factor authentication code.
    """
    user_id = serializers.UUIDField(required=True)
    code = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate(self, attrs):
        user_id = attrs.get('user_id')
        code = attrs.get('code')
        
        try:
            user = User.objects.get(id=user_id)
            
            # Check if user has 2FA enabled
            if not user.two_factor_enabled:
                raise serializers.ValidationError(_("Two-factor authentication is not enabled for this account."))
            
            # Get the user's 2FA device
            device = TwoFactorDevice.objects.filter(user=user, is_active=True, type='totp').first()
            if not device:
                raise serializers.ValidationError(_("No active two-factor authentication device found."))
            
            # Verify the code
            import pyotp
            totp = pyotp.TOTP(device.secret)
            if not totp.verify(code):
                raise serializers.ValidationError(_("Invalid verification code."))
            
            # Update device last used timestamp
            device.last_used_at = timezone.now()
            device.save(update_fields=['last_used_at'])
            
            # Record successful 2FA
            attrs['user'] = user
            return attrs
            
        except User.DoesNotExist:
            raise serializers.ValidationError(_("Invalid user."))
    
    def to_representation(self, instance):
        """
        Return tokens after successful 2FA verification.
        """
        user = instance['user']
        refresh = RefreshToken.for_user(user)
        
        # Create a refresh token record
        request = self.context.get('request')
        UserRefreshToken.objects.create(
            user=user,
            token=str(refresh),
            expires_at=timezone.now() + timezone.timedelta(days=7),
            ip_address=request.META.get('REMOTE_ADDR') if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else ''
        )
        
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data
        }

class TwoFactorEnableSerializer(serializers.Serializer):
    """
    Serializer for enabling two-factor authentication.
    """
    device_name = serializers.CharField(required=True, max_length=100)
    
    def validate(self, attrs):
        user = self.context['request'].user
        code = attrs.get('code')
        
        # Find the most recently created inactive TOTP device
        device = TwoFactorDevice.objects.filter(
            user=user,
            type='totp',
            is_active=True
        ).order_by('-created_at').first()
        
        if not device:
            raise serializers.ValidationError(_("No two-factor authentication device found."))
        
        # Verify the code
        import pyotp
        totp = pyotp.TOTP(device.secret)
        if not totp.verify(code):
            raise serializers.ValidationError(_("Invalid verification code."))
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        
        # Enable 2FA for the user
        user.two_factor_enabled = True
        user.save(update_fields=['two_factor_enabled'])
        
        return user


class TwoFactorDisableSerializer(serializers.Serializer):
    """
    Serializer for disabling two-factor authentication.
    """
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Password is incorrect."))
        return value
    
    def validate(self, attrs):
        user = self.context['request'].user
        
        # Check if user has 2FA enabled
        if not user.two_factor_enabled:
            raise serializers.ValidationError(_("Two-factor authentication is not enabled."))
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        
        # Disable 2FA for the user
        user.two_factor_enabled = False
        user.save(update_fields=['two_factor_enabled'])
        
        # Deactivate all 2FA devices
        TwoFactorDevice.objects.filter(user=user).update(is_active=False)
        
        return user


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer for refreshing access tokens.
    """
    refresh = serializers.CharField(required=True)
    
    def validate(self, attrs):
        refresh_token = attrs.get('refresh')
        
        # Validate the refresh token
        try:
            # Look up the refresh token in our database
            token_record = UserRefreshToken.objects.get(token=refresh_token)
            
            # Check if it's expired or revoked
            if token_record.expires_at < timezone.now():
                # Remove expired token
                token_record.delete()
                raise serializers.ValidationError(_("Refresh token has expired."))
            
            if token_record.revoked_at:
                raise serializers.ValidationError(_("Refresh token has been revoked."))
            
            # Get the user
            user = token_record.user
            
            # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError(_("User account is disabled."))
            
            # Validate with JWT library
            try:
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken(refresh_token)
            except Exception as e:
                # If the JWT library fails to validate, revoke the token
                token_record.revoke()
                raise serializers.ValidationError(str(e))
            
            # Implementation of refresh token rotation: revoke old token
            token_record.revoke()
            
            # Create a new refresh token
            new_refresh = RefreshToken.for_user(user)
            
            # Create a new refresh token record
            request = self.context.get('request')
            new_token_record = UserRefreshToken.objects.create(
                user=user,
                token=str(new_refresh),
                expires_at=timezone.now() + timezone.timedelta(days=7),
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT', '') if request else ''
            )
            
            return {
                'access': str(new_refresh.access_token),
                'refresh': str(new_refresh),
                'user': user
            }
            
        except UserRefreshToken.DoesNotExist:
            raise serializers.ValidationError(_("Invalid refresh token."))


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for logging out and revoking refresh tokens.
    """
    refresh = serializers.CharField(required=False)
    all_devices = serializers.BooleanField(required=False, default=False)
    
    def validate(self, attrs):
        # At least one of refresh or all_devices should be provided
        if not attrs.get('refresh') and not attrs.get('all_devices'):
            raise serializers.ValidationError(_("Either 'refresh' token or 'all_devices' must be provided."))
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        refresh_token = self.validated_data.get('refresh')
        all_devices = self.validated_data.get('all_devices')
        
        if all_devices:
            # Revoke all refresh tokens for the user
            UserRefreshToken.objects.filter(user=user, revoked_at=None).update(revoked_at=timezone.now())
            return {'detail': _("Successfully logged out from all devices.")}
        else:
            # Revoke the specific refresh token
            try:
                token_record = UserRefreshToken.objects.get(token=refresh_token, user=user)
                token_record.revoke()
                return {'detail': _("Successfully logged out.")}
            except UserRefreshToken.DoesNotExist:
                raise serializers.ValidationError(_("Invalid refresh token.")).context['request'].user
        
        # Check if user already has 2FA enabled
        if user.two_factor_enabled:
            raise serializers.ValidationError(_("Two-factor authentication is already enabled."))
        
        # Generate a new TOTP secret
        import pyotp
        secret = pyotp.random_base32()
        
        attrs['secret'] = secret
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        device_name = self.validated_data['device_name']
        secret = self.validated_data['secret']
        
        # Create a new 2FA device
        device = TwoFactorDevice.objects.create(
            user=user,
            name=device_name,
            type='totp',
            secret=secret
        )
        
        # Return the device and QR code provisioning URI
        import pyotp
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(user.email, issuer_name="Authly")
        
        return {
            'device': device,
            'secret': secret,
            'provisioning_uri': provisioning_uri
        }

class TwoFactorConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming two-factor authentication setup.
    """
    code = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate(self, attrs):
        user = self.context['request'].user
        
        # Check if user has 2FA enabled
        if not user.two_factor_enabled:
            raise serializers.ValidationError(_("Two-factor authentication is not enabled."))
        
        # Get the user's 2FA device
        device = TwoFactorDevice.objects.filter(user=user, is_active=True, type='totp').first()
        if not device:
            raise serializers.ValidationError(_("No active two-factor authentication device found."))
        
        # Verify the code
        import pyotp
        totp = pyotp.TOTP(device.secret)
        if not totp.verify(attrs['code']):
            raise serializers.ValidationError(_("Invalid verification code."))
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        
        # Mark the 2FA setup as complete
        user.two_factor_setup_complete = True
        user.save(update_fields=['two_factor_setup_complete'])
        
        return user