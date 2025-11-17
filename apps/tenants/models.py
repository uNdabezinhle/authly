from django_tenants.models import TenantMixin, DomainMixin
from django.db import models
import uuid

class Tenant(TenantMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, help_text="Organization name")
    slug = models.SlugField(unique=True, help_text="URL-friendly identifier")
    description = models.TextField(blank=True, help_text="Optional description")
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)
    
    # Subscription info
    plan = models.CharField(max_length=50, default='free', help_text="Subscription plan")
    max_users = models.PositiveIntegerField(default=50, help_text="Maximum users allowed")
    
    # Contact info
    contact_email = models.EmailField(blank=True, help_text="Primary contact email")
    contact_phone = models.CharField(max_length=20, blank=True)
    
    auto_create_schema = True
    auto_drop_schema = True
    
    class Meta:
        ordering = ['name']
        
    def __str__(self):
        return self.name

class Domain(DomainMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_on = models.DateTimeField(auto_now_add=True)
