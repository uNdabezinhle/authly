from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AuthViewSet, MFAViewSet, LogoutView, SessionViewSet
from .docs_views import swagger_login, test_auth

router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'mfa', MFAViewSet, basename='mfa')
router.register(r'sessions', SessionViewSet, basename='sessions')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    
    # Swagger UI specific endpoints
    path('docs/login/', swagger_login, name='swagger-login'),
    path('docs/test-auth/', test_auth, name='test-auth'),
]