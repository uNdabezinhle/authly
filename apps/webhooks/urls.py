from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import WebhookViewSet, WebhookDeliveryViewSet

router = DefaultRouter()
router.register(r'webhooks', WebhookViewSet, basename='webhooks')
router.register(r'deliveries', WebhookDeliveryViewSet, basename='webhook-deliveries')

urlpatterns = [path('', include(router.urls))]
