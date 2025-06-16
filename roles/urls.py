# roles/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RoleViewSet, PermissionViewSet, GroupViewSet, ABACRuleViewSet

router = DefaultRouter()
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'groups', GroupViewSet)
router.register(r'abac-rules', ABACRuleViewSet)

urlpatterns = [
    path('', include(router.urls)),
]