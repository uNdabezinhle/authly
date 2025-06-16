from django.urls import path
from .views import TenantListCreateView, TenantRetrieveUpdateDestroyView

urlpatterns = [
    path('', TenantListCreateView.as_view(), name='tenant-list-create'),
    path('<uuid:pk>/', TenantRetrieveUpdateDestroyView.as_view(), name='tenant-detail'),
]