# api_keys/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import APIKeyViewSet

router = DefaultRouter()
router.register(r'', APIKeyViewSet)

urlpatterns = [
    path('', include(router.urls)),
]