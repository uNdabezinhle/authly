from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentication endpoints
    path('api/auth/', include('users.urls.auth_urls')),
    
    # User management endpoints
    path('api/users/', include('users.urls.user_urls')),
    
    # Role and permission management endpoints
    path('api/roles/', include('roles.urls')),
    
    # API key management endpoints
    path('api/api-keys/', include('api_keys.urls')),
    
    # OAuth2 endpoints
    path('api/oauth2/', include('oauth2.urls')),
    
    # SSO endpoints (new)
    path('api/sso/', include('sso.urls')),
    
    # API documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)