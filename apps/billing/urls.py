from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'billing'

router = DefaultRouter()
router.register(r'plans', views.BillingPlanViewSet, basename='billing-plans')
router.register(r'subscription', views.TenantSubscriptionViewSet, basename='tenant-subscription')
router.register(r'invoices', views.InvoiceViewSet, basename='invoices')
router.register(r'payment-methods', views.PaymentMethodViewSet, basename='payment-methods')
router.register(r'usage', views.UsageRecordViewSet, basename='usage-records')
router.register(r'events', views.BillingEventViewSet, basename='billing-events')

urlpatterns = [
    path('api/v1/', include(router.urls)),
]