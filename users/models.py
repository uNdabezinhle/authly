# users/models.py

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField

class UserManager(BaseUserManager):
    """
    Custom user manager for the User model.
    """
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a regular user with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model with email as the unique identifier.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    username = models.CharField(_('username'), max_length=150, unique=True, blank=True, null=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    phone_number = PhoneNumberField(_('phone number'), blank=True, null=True)
    
    # Timestamp fields
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_login = models.DateTimeField(_('last login'), blank=True, null=True)
    
    # Status fields
    is_active = models.BooleanField(_('active'), default=True)
    is_staff = models.BooleanField(_('staff status'), default=False)
    
    # 2FA fields
    two_factor_enabled = models.BooleanField(_('two-factor authentication enabled'), default=False)
    
    # Profile fields
    bio = models.TextField(_('bio'), blank=True)
    profile_picture = models.ImageField(_('profile picture'), upload_to='profile_pictures/', blank=True, null=True)
    
    # Password management fields
    password_changed_at = models.DateTimeField(_('password changed at'), blank=True, null=True)
    password_expires_at = models.DateTimeField(_('password expires at'), blank=True, null=True)
    password_history = models.JSONField(_('password history'), default=list, blank=True)
    failed_login_attempts = models.PositiveIntegerField(_('failed login attempts'), default=0)
    locked_until = models.DateTimeField(_('locked until'), blank=True, null=True)
    
    # Account verification fields
    email_verified = models.BooleanField(_('email verified'), default=False)
    phone_verified = models.BooleanField(_('phone verified'), default=False)
    
    # Social auth fields
    social_provider = models.CharField(_('social provider'), max_length=50, blank=True)
    social_id = models.CharField(_('social ID'), max_length=255, blank=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['email']

    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()
    
    def get_short_name(self):
        """
        Return the short name for the user.
        """
        return self.first_name
    
    def lock_account(self, duration_minutes=30):
        """
        Lock the account for a specified duration after too many failed login attempts.
        """
        self.locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save(update_fields=['locked_until'])
    
    def unlock_account(self):
        """
        Unlock the account and reset failed login attempts.
        """
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['locked_until', 'failed_login_attempts'])
    
    def is_locked(self):
        """
        Check if the account is currently locked.
        """
        if self.locked_until and self.locked_until > timezone.now():
            return True
        if self.locked_until:  # If lock has expired
            self.unlock_account()
        return False
    
    def record_login_failure(self, max_attempts=5):
        """
        Record a failed login attempt and lock the account if max attempts exceeded.
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.lock_account()
        else:
            self.save(update_fields=['failed_login_attempts'])
    
    def record_login_success(self):
        """
        Record a successful login by updating last_login and resetting failed attempts.
        """
        self.last_login = timezone.now()
        self.failed_login_attempts = 0
        self.save(update_fields=['last_login', 'failed_login_attempts'])
    
    def add_to_password_history(self, password_hash, max_history=5):
        """
        Add a password hash to the user's password history.
        """
        history = self.password_history or []
        history.append({
            'password': password_hash,
            'date': timezone.now().isoformat()
        })
        
        # Keep only the most recent passwords up to max_history
        if len(history) > max_history:
            history = history[-max_history:]
        
        self.password_history = history
        self.save(update_fields=['password_history'])
        
    def set_password_expiry(self, days=90):
        """
        Set the password expiration date.
        """
        self.password_expires_at = timezone.now() + timezone.timedelta(days=days)
        self.save(update_fields=['password_expires_at'])
    
    def is_password_expired(self):
        """
        Check if the user's password has expired.
        """
        if not self.password_expires_at:
            return False
        return self.password_expires_at < timezone.now()


class TwoFactorDevice(models.Model):
    """
    Model for storing two-factor authentication device information.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='two_factor_devices')
    name = models.CharField(_('device name'), max_length=100)
    type = models.CharField(_('device type'), max_length=20, choices=(
        ('totp', _('Time-based OTP')),
        ('sms', _('SMS')),
        ('email', _('Email')),
    ))
    secret = models.CharField(_('secret key'), max_length=550)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    last_used_at = models.DateTimeField(_('last used at'), blank=True, null=True)
    is_active = models.BooleanField(_('active'), default=True)
    
    class Meta:
        verbose_name = _('two-factor device')
        verbose_name_plural = _('two-factor devices')
        unique_together = ('user', 'name')
    
    def __str__(self):
        return f"{self.user.email}'s {self.name} ({self.type})"


class RefreshToken(models.Model):
    """
    Model for storing refresh tokens.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.CharField(_('token'), max_length=550, unique=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'))
    revoked_at = models.DateTimeField(_('revoked at'), blank=True, null=True)
    ip_address = models.GenericIPAddressField(_('IP address'), blank=True, null=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    
    class Meta:
        verbose_name = _('refresh token')
        verbose_name_plural = _('refresh tokens')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Token for {self.user.email} ({self.id})"
    
    def is_valid(self):
        """
        Check if the token is valid (not expired or revoked).
        """
        return not self.is_expired() and not self.is_revoked()
    
    def is_expired(self):
        """
        Check if the token has expired.
        """
        return self.expires_at < timezone.now()
    
    def is_revoked(self):
        """
        Check if the token has been revoked.
        """
        return self.revoked_at is not None
    
    def revoke(self):
        """
        Revoke the token.
        """
        self.revoked_at = timezone.now()
        self.save(update_fields=['revoked_at'])