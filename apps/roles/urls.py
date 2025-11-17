from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PermissionViewSet, RoleViewSet, UserRoleViewSet, 
    DelegatedRoleViewSet, AdminRoleManagementViewSet
)

router = DefaultRouter()
router.register(r'permissions', PermissionViewSet, basename='permissions')
router.register(r'roles', RoleViewSet, basename='roles')
router.register(r'user-roles', UserRoleViewSet, basename='user-roles')
router.register(r'delegated-roles', DelegatedRoleViewSet, basename='delegated-roles')
router.register(r'admin', AdminRoleManagementViewSet, basename='admin-roles')

urlpatterns = [path('', include(router.urls))]
