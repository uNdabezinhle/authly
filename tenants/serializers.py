from rest_framework import serializers
from .models import Tenant

class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ['id', 'name', 'created_at']