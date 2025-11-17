from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'tokens'

router = DefaultRouter()
router.register(r'scopes', views.TokenScopeViewSet, basename='token-scopes')
router.register(r'tokens', views.ScopedTokenViewSet, basename='scoped-tokens')
router.register(r'revocations', views.TokenRevocationViewSet, basename='token-revocations')

urlpatterns = [
    path('api/v1/', include(router.urls)),
]