from django.shortcuts import render
from rest_framework import generics
from .models import Tenant
from .serializers import TenantSerializer

# Create your views here.

class TenantListCreateView(generics.ListCreateAPIView):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer

class TenantRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
