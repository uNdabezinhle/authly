# users/urls/auth_urls.py

from django.urls import path
from users.views.auth_views import (
    LoginView,
    TwoFactorVerifyView,
    TwoFactorEnableView,
    TwoFactorConfirmView,
    TwoFactorDisableView,
    PasswordChangeView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    RefreshTokenView,
    LogoutView,
    SessionView
)

urlpatterns = [
    # Authentication
    path('login/', LoginView.as_view(), name='auth-login'),
    path('logout/', LogoutView.as_view(), name='auth-logout'),
    path('refresh/', RefreshTokenView.as_view(), name='auth-refresh'),
    path('session/', SessionView.as_view(), name='auth-session'),
    
    # Two-factor authentication
    path('2fa/verify/', TwoFactorVerifyView.as_view(), name='auth-2fa-verify'),
    path('2fa/enable/', TwoFactorEnableView.as_view(), name='auth-2fa-enable'),
    path('2fa/confirm/', TwoFactorConfirmView.as_view(), name='auth-2fa-confirm'),
    path('2fa/disable/', TwoFactorDisableView.as_view(), name='auth-2fa-disable'),
    
    # Password management
    path('password/change/', PasswordChangeView.as_view(), name='auth-password-change'),
    path('password/reset/', PasswordResetRequestView.as_view(), name='auth-password-reset'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='auth-password-reset-confirm'),
]