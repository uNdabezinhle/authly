from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'customization'

router = DefaultRouter()
router.register(r'branding', views.TenantBrandingViewSet, basename='tenant-branding')
router.register(r'email-templates', views.EmailTemplateViewSet, basename='email-templates')
router.register(r'usage-metrics', views.TenantUsageMetricsViewSet, basename='usage-metrics')
router.register(r'exports', views.DataExportViewSet, basename='data-exports')
router.register(r'compliance', views.ComplianceSettingsViewSet, basename='compliance-settings')
router.register(r'onboarding', views.OnboardingViewSet, basename='onboarding')

urlpatterns = [
    path('api/v1/', include(router.urls)),
]