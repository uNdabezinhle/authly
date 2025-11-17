# authly_api/settings.py
import os
from pathlib import Path
from datetime import timedelta
from decouple import config, Csv

BASE_DIR = Path(__file__).resolve().parent.parent

# =========================================================================
# DJANGO CORE SETTINGS
# =========================================================================
SECRET_KEY = config('DJANGO_SECRET_KEY', default='dev-secret-key-change-in-prod')
DEBUG = config('DJANGO_DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = config('DJANGO_ALLOWED_HOSTS', default='*', cast=Csv())
ENVIRONMENT = config('DJANGO_ENVIRONMENT', default='development')

# Feature flags
FEATURE_FLAGS = {
    'SSO_ENABLED': config('FEATURE_SSO_ENABLED', default=True, cast=bool),
    'MFA_ENABLED': config('FEATURE_MFA_ENABLED', default=True, cast=bool),
    'WEBHOOKS_ENABLED': config('FEATURE_WEBHOOKS_ENABLED', default=True, cast=bool),
    'API_KEYS_ENABLED': config('FEATURE_API_KEYS_ENABLED', default=True, cast=bool),
    'AUDIT_LOGS_ENABLED': config('FEATURE_AUDIT_LOGS_ENABLED', default=True, cast=bool),
    'SCOPED_TOKENS_ENABLED': config('FEATURE_SCOPED_TOKENS_ENABLED', default=True, cast=bool),
    'TENANT_BRANDING_ENABLED': config('FEATURE_TENANT_BRANDING_ENABLED', default=True, cast=bool),
    'DATA_EXPORTS_ENABLED': config('FEATURE_DATA_EXPORTS_ENABLED', default=True, cast=bool),
    'ONBOARDING_ENABLED': config('FEATURE_ONBOARDING_ENABLED', default=True, cast=bool),
}

# === DJANGO-TENANTS CONFIG ===
TENANT_MODEL = "tenants.Tenant"
TENANT_DOMAIN_MODEL = "tenants.Domain"

# Apps that live **in every tenant schema**
TENANT_APPS = [
    'django_otp',
    'django_otp.plugins.otp_totp',
    'apps.authentication',
    'apps.roles',
    'apps.api_keys',
    'apps.webhooks',
    'apps.audit',
    'apps.federation',
    'apps.tokens',
    'apps.customization',
    'apps.billing',
]

# Apps that live **only in the public schema**
SHARED_APPS = [
    'django_tenants',
    'django.contrib.contenttypes',   # ← Only here
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    
    # Third party
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_spectacular',
    'django_filters',
    'django_ratelimit',

    'apps.tenants',
    'apps.users',  # Must be in SHARED_APPS since it contains AUTH_USER_MODEL
]

# Final list – SHARED + TENANT
INSTALLED_APPS = SHARED_APPS + TENANT_APPS

# -------------------------------------------------------------------------
# MIDDLEWARE
# -------------------------------------------------------------------------
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# -------------------------------------------------------------------------
# URLS
# -------------------------------------------------------------------------
ROOT_URLCONF = 'authly_api.urls'
PUBLIC_SCHEMA_URLCONF = 'authly_api.urls_public'

# -------------------------------------------------------------------------
# TEMPLATES
# -------------------------------------------------------------------------
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'authly_api.wsgi.application'

# =========================================================================
# DATABASE CONFIGURATION
# =========================================================================
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': config('POSTGRES_DB', default='authly_api'),
        'USER': config('POSTGRES_USER', default='postgres'),
        'PASSWORD': config('POSTGRES_PASSWORD', default='postgres'),
        'HOST': config('POSTGRES_HOST', default='localhost'),
        'PORT': config('POSTGRES_PORT', default='5432'),
        'OPTIONS': {
            'connect_timeout': 10,
            'options': '-c default_transaction_isolation=serializable'
        },
        'CONN_MAX_AGE': 600,
    }
}

# -------------------------------------------------------------------------
# AUTH
# -------------------------------------------------------------------------
AUTH_USER_MODEL = 'users.User'

# -------------------------------------------------------------------------
# REST FRAMEWORK
# -------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# =========================================================================
# JWT & AUTHENTICATION
# =========================================================================
JWT_ISSUER = config('JWT_ISSUER', default='authly-api')
JWT_ALGORITHM = config('JWT_ALGORITHM', default='HS256')

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=config('JWT_ACCESS_TOKEN_LIFETIME', default=15, cast=int)),
    'REFRESH_TOKEN_LIFETIME': timedelta(minutes=config('JWT_REFRESH_TOKEN_LIFETIME', default=10080, cast=int)),
    'ROTATE_REFRESH_TOKENS': config('JWT_ROTATE_REFRESH_TOKENS', default=True, cast=bool),
    'ALGORITHM': JWT_ALGORITHM,
    'ISSUER': JWT_ISSUER,
}

# -------------------------------------------------------------------------
# OPENAPI (drf-spectacular)
# -------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    'TITLE': 'Authly API',
    'DESCRIPTION': 'Enterprise Identity & Access Management API - Multi-tenant SaaS platform for identity management, user authentication, role-based access control, and audit logging.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'CONTACT': {
        'name': 'Authly Support',
        'email': 'support@authly.com',
    },
    'LICENSE': {
        'name': 'MIT License',
    },
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': True,
        'defaultModelExpandDepth': 2,
        'defaultModelsExpandDepth': 2,
        'filter': True,
        'tagsSorter': 'alpha',
        'operationsSorter': 'alpha',
    },
    'AUTHENTICATION_WHITELIST': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'SECURITY': [
        {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        }
    ],
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'Enter: **Bearer &lt;JWT token&gt;**',
        }
    },
    'SCHEMA_PATH_PREFIX': '/api/',
    'SERVERS': [
        {
            'url': 'http://localhost:8000',
            'description': 'Local development server'
        },
        {
            'url': 'https://{tenant}.authly.com',
            'description': 'Production server',
            'variables': {
                'tenant': {
                    'default': 'demo',
                    'description': 'Tenant subdomain'
                }
            }
        }
    ],
}

# =========================================================================
# STATIC & MEDIA FILES
# =========================================================================
STATIC_URL = '/static/'
STATIC_ROOT = config('STATIC_ROOT', default=str(BASE_DIR / 'staticfiles'))

MEDIA_URL = '/media/'
MEDIA_ROOT = config('MEDIA_ROOT', default=str(BASE_DIR / 'media'))

# AWS S3 Configuration (optional)
USE_S3_STORAGE = config('USE_S3_STORAGE', default=False, cast=bool)
if USE_S3_STORAGE:
    AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
    AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
    AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default='us-east-1')
    AWS_DEFAULT_ACL = None
    AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
    
    # Static files storage
    STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

# =========================================================================
# EMAIL CONFIGURATION
# =========================================================================
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@authly.com')
SUPPORT_EMAIL = config('SUPPORT_EMAIL', default='support@authly.com')

EMAIL_HOST = config('EMAIL_HOST', default='localhost')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')

# -------------------------------------------------------------------------
# DJANGO-OTP
# -------------------------------------------------------------------------
OTP_TOTP_ISSUER = 'Authly'

# === DATABASE ROUTING ===
DATABASE_ROUTERS = ['django_tenants.routers.TenantSyncRouter']

# =========================================================================
# CELERY CONFIGURATION
# =========================================================================
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default=CELERY_BROKER_URL)
CELERY_TASK_SERIALIZER = config('CELERY_TASK_SERIALIZER', default='json')
CELERY_ACCEPT_CONTENT = [config('CELERY_ACCEPT_CONTENT', default='json')]
CELERY_TIMEZONE = config('CELERY_TIMEZONE', default='UTC')
CELERY_BEAT_SCHEDULE_ENABLED = config('CELERY_BEAT_SCHEDULE_ENABLED', default=True, cast=bool)

# =========================================================================
# SECURITY SETTINGS
# =========================================================================
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=False, cast=bool)
SECURE_PROXY_SSL_HEADER = (
    config('SECURE_PROXY_SSL_HEADER_NAME', default='HTTP_X_FORWARDED_PROTO'),
    config('SECURE_PROXY_SSL_HEADER_VALUE', default='https')
) if not DEBUG else None

CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=False, cast=bool)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
SECURE_BROWSER_XSS_FILTER = config('SECURE_BROWSER_XSS_FILTER', default=True, cast=bool)
SECURE_CONTENT_TYPE_NOSNIFF = config('SECURE_CONTENT_TYPE_NOSNIFF', default=True, cast=bool)
X_FRAME_OPTIONS = config('X_FRAME_OPTIONS', default='DENY')

# =========================================================================
# COMPLIANCE & GDPR
# =========================================================================
GDPR_ENABLED = config('GDPR_ENABLED', default=True, cast=bool)
DATA_RETENTION_DAYS = config('DATA_RETENTION_DAYS', default=2555, cast=int)
AUDIT_LOG_RETENTION_DAYS = config('AUDIT_LOG_RETENTION_DAYS', default=2555, cast=int)
AUTOMATIC_DATA_DELETION = config('AUTOMATIC_DATA_DELETION', default=False, cast=bool)
BREACH_NOTIFICATION_EMAIL = config('BREACH_NOTIFICATION_EMAIL', default='security@authly.com')
COMPLIANCE_FRAMEWORKS = config('COMPLIANCE_FRAMEWORK', default='GDPR,SOC2', cast=Csv())

# =========================================================================
# BILLING & STRIPE
# =========================================================================
BILLING_ENABLED = config('BILLING_ENABLED', default=True, cast=bool)
STRIPE_PUBLISHABLE_KEY = config('STRIPE_PUBLISHABLE_KEY', default='')
STRIPE_SECRET_KEY = config('STRIPE_SECRET_KEY', default='')
STRIPE_WEBHOOK_SECRET = config('STRIPE_WEBHOOK_SECRET', default='')
BILLING_CURRENCY = config('BILLING_CURRENCY', default='USD')
BILLING_TAX_RATE = config('BILLING_TAX_RATE', default=0.08, cast=float)

# =========================================================================
# EXTERNAL SERVICES
# =========================================================================
SENDGRID_API_KEY = config('SENDGRID_API_KEY', default='')
TWILIO_ACCOUNT_SID = config('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = config('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = config('TWILIO_PHONE_NUMBER', default='')

# =========================================================================
# MONITORING & LOGGING
# =========================================================================
LOG_LEVEL = config('LOG_LEVEL', default='INFO')
SENTRY_DSN = config('SENTRY_DSN', default='')
DATADOG_API_KEY = config('DATADOG_API_KEY', default='')
PROMETHEUS_ENABLED = config('PROMETHEUS_ENABLED', default=True, cast=bool)

# Configure Sentry if DSN is provided
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(auto_enabling_integrations=True),
            CeleryIntegration(monitor_beat_tasks=True),
        ],
        environment=ENVIRONMENT,
        traces_sample_rate=0.1,
        send_default_pii=False,
    )

# =========================================================================
# RATE LIMITING
# =========================================================================
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_VIEW = 'apps.core.views.ratelimited'

# API Rate limits from environment
API_RATE_LIMITS = {
    'LOGIN': config('API_RATE_LIMIT_LOGIN', default='10/m'),
    'REGISTER': config('API_RATE_LIMIT_REGISTER', default='5/m'),
    'PASSWORD_RESET': config('API_RATE_LIMIT_PASSWORD_RESET', default='3/h'),
    'TOKEN_CREATE': config('API_RATE_LIMIT_TOKEN_CREATE', default='10/h'),
    'DEFAULT': config('API_RATE_LIMIT_DEFAULT', default='1000/h'),
}

# =========================================================================
# REDIS CACHE
# =========================================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': config('REDIS_CACHE_URL', default='redis://127.0.0.1:6379/1'),
        'TIMEOUT': 300,
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 20,
                'retry_on_timeout': True,
            }
        }
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# =========================================================================
# DEVELOPMENT SETTINGS
# =========================================================================
if DEBUG:
    DEV_TOOLBAR_ENABLED = config('DEV_TOOLBAR_ENABLED', default=False, cast=bool)
    if DEV_TOOLBAR_ENABLED:
        INSTALLED_APPS += ['debug_toolbar']
        MIDDLEWARE = ['debug_toolbar.middleware.DebugToolbarMiddleware'] + MIDDLEWARE
        INTERNAL_IPS = ['127.0.0.1']
    
    # SQL query logging
    DEBUG_LOG_SQL = config('DEBUG_LOG_SQL', default=False, cast=bool)
    if DEBUG_LOG_SQL:
        LOGGING['loggers']['django.db.backends'] = {
            'level': 'DEBUG',
            'handlers': ['console'],
            'propagate': False,
        }