from django.contrib import admin
from .models import User, TwoFactorDevice, RefreshToken

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'is_active', 'is_staff', 'tenant')
    list_filter = ('tenant', 'is_active', 'is_staff')

@admin.register(TwoFactorDevice)
class TwoFactorDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'type', 'is_active', 'tenant', 'created_at')
    list_filter = ('tenant', 'type', 'is_active')

@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'tenant', 'created_at', 'expires_at', 'revoked_at')
    list_filter = ('tenant', 'created_at', 'expires_at', 'revoked_at')
