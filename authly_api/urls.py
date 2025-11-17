from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='docs'),
    path('api/tenants/', include('apps.tenants.urls')),
    path('api/users/', include('apps.users.urls')),
    path('api/auth/', include('apps.authentication.urls')),
    path('api/roles/', include('apps.roles.urls')),
    path('api/api-keys/', include('apps.api_keys.urls')),
    path('api/webhooks/', include('apps.webhooks.urls')),
    path('api/audit/', include('apps.audit.urls')),
    path('api/federation/', include('apps.federation.urls')),
    path('api/tokens/', include('apps.tokens.urls')),
    path('api/customization/', include('apps.customization.urls')),
    path('api/billing/', include('apps.billing.urls')),
]
