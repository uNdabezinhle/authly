# sso/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    IdentityProviderViewSet,
    SSOUserMappingViewSet,
    SSOSessionViewSet,
    SSOLoginInitView,
    SSOLDAPLoginView,
    SSOCallbackView,
    SSOCallbackAPIView
)

router = DefaultRouter()
router.register(r'providers', IdentityProviderViewSet)
router.register(r'mappings', SSOUserMappingViewSet)
router.register(r'sessions', SSOSessionViewSet)

urlpatterns = [
    # Router URLs for CRUD operations
    path('', include(router.urls)),
    
    # SSO login flows
    path('login/init/', SSOLoginInitView.as_view(), name='sso-login-init'),
    path('login/ldap/', SSOLDAPLoginView.as_view(), name='sso-login-ldap'),
    
    # SSO callbacks
    path('callback/<uuid:provider_id>/', SSOCallbackView.as_view(), name='sso-callback'),
    path('callback/api/', SSOCallbackAPIView.as_view(), name='sso-callback-api'),
]