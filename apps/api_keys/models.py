# apps/api_keys/models.py
import secrets
from django.db import models
from django.contrib.auth.hashers import make_password

class APIKey(models.Model):
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=8, unique=True)
    hashed_key = models.CharField(max_length=128)
    user = models.ForeignKey('users.User', on_delete=models.CASCADE)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    scopes = models.JSONField(default=list)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    @classmethod
    def create_key(cls, **kwargs):
        prefix = secrets.token_hex(4)
        raw_key = f"{prefix}_{secrets.token_urlsafe(32)}"
        hashed = make_password(raw_key)
        obj = cls.objects.create(prefix=prefix, hashed_key=hashed, **kwargs)
        return obj, raw_key