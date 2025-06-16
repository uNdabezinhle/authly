# sso/apps.py

from django.apps import AppConfig


class SSOConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sso'
    verbose_name = 'Single Sign-On'