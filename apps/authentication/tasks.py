from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_activation_email(user_id, user_email, tenant_domain):
    """Send account activation email"""
    try:
        from apps.users.models import User
        user = User.objects.get(id=user_id)
        
        # Generate activation token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Prepare email context
        context = {
            'user': user,
            'activation_url': f"https://{tenant_domain}/api/auth/activate/{uid}/{token}/",
            'site_name': 'Authly',
            'tenant_domain': tenant_domain,
        }
        
        # Render email template
        html_message = render_to_string('emails/activation.html', context)
        plain_message = f"""
Welcome to Authly!

Please activate your account by clicking the link below:
{context['activation_url']}

If you didn't create this account, please ignore this email.

Best regards,
The Authly Team
        """
        
        # Send email
        send_mail(
            subject='Activate Your Authly Account',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Activation email sent to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send activation email to {user_email}: {str(e)}")
        return False

@shared_task
def send_password_reset_email(user_id, user_email, tenant_domain):
    """Send password reset email"""
    try:
        from apps.users.models import User
        user = User.objects.get(id=user_id)
        
        # Generate reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Prepare email context
        context = {
            'user': user,
            'reset_url': f"https://{tenant_domain}/api/auth/reset-password/{uid}/{token}/",
            'site_name': 'Authly',
            'tenant_domain': tenant_domain,
        }
        
        # Render email template
        html_message = render_to_string('emails/password_reset.html', context)
        plain_message = f"""
Password Reset Request

You requested a password reset for your Authly account. Click the link below to reset your password:
{context['reset_url']}

If you didn't request this, please ignore this email.

Best regards,
The Authly Team
        """
        
        # Send email
        send_mail(
            subject='Reset Your Authly Password',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Password reset email sent to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user_email}: {str(e)}")
        return False

@shared_task
def send_verification_email(user_id, user_email, tenant_domain):
    """Send email verification email (separate from activation)"""
    try:
        from apps.users.models import User
        user = User.objects.get(id=user_id)
        
        # Generate verification token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Prepare email context
        context = {
            'user': user,
            'verification_url': f"https://{tenant_domain}/api/auth/verify-email/{uid}/{token}/",
            'site_name': 'Authly',
            'tenant_domain': tenant_domain,
        }
        
        # For now, we'll use a simple email format
        # In production, you'd have a proper email template
        plain_message = f"""
Email Verification Required

Please verify your email address by clicking the link below:
{context['verification_url']}

If you didn't request this verification, please ignore this email.

Best regards,
The Authly Team
        """
        
        # Send email
        send_mail(
            subject='Verify Your Email Address',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            fail_silently=False,
        )
        
        logger.info(f"Email verification sent to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send verification email to {user_email}: {str(e)}")
        return False