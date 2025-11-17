from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.core.files.storage import default_storage
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        read_only_fields = ['id', 'last_login', 'date_joined', 'is_staff', 'is_superuser']
        extra_kwargs = {'password': {'write_only': True}}


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'preferred_name',
            'phone', 'bio', 'avatar', 'email_verified', 'mfa_enabled',
            'privacy_email', 'privacy_phone', 'privacy_name',
            'privacy_avatar', 'privacy_bio', 'date_joined'
        ]
        read_only_fields = ['id', 'email', 'email_verified', 'mfa_enabled', 'date_joined']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        # Always show full data to the user themselves
        if not request or not request.user.is_authenticated or request.user == instance:
            return data
        
        viewer = request.user
        
        # Apply privacy controls based on user privacy settings
        if instance.privacy_email != 'public':
            if (instance.privacy_email == 'private' or 
                (instance.privacy_email == 'tenant' and viewer.tenant != instance.tenant)):
                data['email'] = None
        
        if instance.privacy_phone != 'public':
            if (instance.privacy_phone == 'private' or 
                (instance.privacy_phone == 'tenant' and viewer.tenant != instance.tenant)):
                data['phone'] = ''
        
        if instance.privacy_name != 'public':
            if (instance.privacy_name == 'private' or 
                (instance.privacy_name == 'tenant' and viewer.tenant != instance.tenant)):
                data['first_name'] = data['last_name'] = data['preferred_name'] = ''
        
        if instance.privacy_avatar != 'public':
            if (instance.privacy_avatar == 'private' or 
                (instance.privacy_avatar == 'tenant' and viewer.tenant != instance.tenant)):
                data['avatar'] = None
        
        if instance.privacy_bio != 'public':
            if (instance.privacy_bio == 'private' or 
                (instance.privacy_bio == 'tenant' and viewer.tenant != instance.tenant)):
                data['bio'] = ''
        
        return data


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'preferred_name', 'phone', 'bio',
            'privacy_email', 'privacy_phone', 'privacy_name',
            'privacy_avatar', 'privacy_bio'
        ]

    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value.strip()

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value.strip()


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password_confirm": "Password confirmation doesn't match."})
        return attrs

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class AvatarUploadSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(write_only=True)

    class Meta:
        model = User
        fields = ['avatar']

    def validate_avatar(self, value):
        # Check file extension
        allowed_extensions = ['.png', '.jpg', '.jpeg']
        file_extension = value.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            raise serializers.ValidationError(
                "Invalid file type. Only PNG, JPG, and JPEG files are allowed."
            )
        
        # Check file size (limit to 5MB)
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError(
                "File size too large. Maximum allowed size is 5MB."
            )
        
        return value

    def update(self, instance, validated_data):
        # Delete old avatar before saving new one
        if instance.avatar:
            try:
                default_storage.delete(instance.avatar.name)
            except Exception:
                pass  # Continue if deletion fails
        
        return super().update(instance, validated_data)
