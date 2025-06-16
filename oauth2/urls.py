# oauth2/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    OAuth2ClientViewSet,
    AuthorizeView,
    TokenView,
    UserinfoView,
    jwks_json,
    revoke_token
)

router = DefaultRouter()
router.register(r'clients', OAuth2ClientViewSet)

urlpatterns = [
    # Client management
    path('', include(router.urls)),
    
    # OAuth2 endpoints
    path('authorize/', AuthorizeView.as_view(), name='oauth2-authorize'),
    path('token/', TokenView.as_view(), name='oauth2-token'),
    path('userinfo/', UserinfoView.as_view(), name='oauth2-userinfo'),
    path('revoke/', revoke_token, name='oauth2-revoke'),
    
    # Discovery endpoints
    path('.well-known/jwks.json', jwks_json, name='oauth2-jwks-json'),
]