# 🔐 Authly API - Enterprise Identity & Access Management Platform

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Django](https://img.shields.io/badge/django-4.2+-green.svg)](https://djangoproject.com/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-12+-blue.svg)](https://postgresql.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Enterprise-grade multi-tenant Django REST API for Identity & Access Management. Provides authentication, authorization, user management, billing, and comprehensive audit capabilities with PostgreSQL schema-based tenant isolation.

## 🌟 Features

### 🔐 **Core Identity & Access Management**
- **Multi-tenant Architecture**: PostgreSQL schema-based tenant isolation
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Role-Based Access Control (RBAC)**: Granular permissions and role management
- **Multi-Factor Authentication**: TOTP-based 2FA support
- **API Key Management**: Service-to-service authentication
- **Comprehensive Audit Logging**: Full activity tracking and compliance

### 💳 **Enterprise Billing & Subscriptions**
- **Stripe Integration**: Complete payment processing
- **Subscription Management**: Flexible billing plans and cycles
- **Usage Tracking**: Metered billing and usage analytics
- **Invoice Management**: Automated invoice generation and delivery
- **Payment Methods**: Multiple payment method support

### 🔗 **Advanced Integration**
- **Webhook System**: Real-time event notifications
- **Federation Support**: SAML/OIDC integration capabilities
- **Scoped Tokens**: Fine-grained API access control
- **Custom Branding**: Tenant-specific customization
- **Data Export**: GDPR-compliant data portability

### 📊 **Enterprise Features**
- **OpenAPI Documentation**: Interactive API documentation
- **Rate Limiting**: API protection and abuse prevention
- **Background Tasks**: Celery-based asynchronous processing
- **Monitoring**: Prometheus metrics and Sentry integration
- **Cloud Storage**: S3-compatible file storage

## 🛠 Technology Stack

- **Backend**: Django 4.2+ with Django REST Framework
- **Database**: PostgreSQL 12+ with tenant schemas
- **Authentication**: JWT with SimpleJWT
- **Caching**: Redis for sessions and background tasks
- **Task Queue**: Celery with Redis broker
- **Payments**: Stripe API integration
- **Documentation**: drf-spectacular (OpenAPI 3.0)
- **Monitoring**: Sentry, Prometheus, Django Debug Toolbar

## 📋 Prerequisites

Before setting up Authly API, ensure you have the following installed:

- **Python 3.9+** (Python 3.10+ recommended)
- **PostgreSQL 12+** with superuser access
- **Redis 6.0+** for caching and task queue
- **Git** for version control

### Optional but Recommended
- **Docker & Docker Compose** for containerized development
- **Node.js & npm** for frontend development tools
- **pgAdmin** for PostgreSQL management

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/authly-api.git
cd authly-api
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip
```

### 3. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# For development (optional)
pip install -r requirements-dev.txt  # If you have dev requirements
```

### 4. Set Up PostgreSQL Database

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Create database and user
CREATE DATABASE authly_api;
CREATE USER authly_user WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE authly_api TO authly_user;
ALTER USER authly_user CREATEDB;  # Required for django-tenants
\q
```

### 5. Configure Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env  # If example exists, or create manually
```

Add the following essential configuration to your `.env` file:

```bash
# =============================================================================
# DJANGO CORE SETTINGS
# =============================================================================
DJANGO_SECRET_KEY=your-super-secret-key-change-in-production-minimum-50-chars
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,*.authly.com,*.yourdomain.com
DJANGO_ENVIRONMENT=development

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
POSTGRES_DB=authly_api
POSTGRES_USER=authly_user
POSTGRES_PASSWORD=your-secure-password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# =============================================================================
# REDIS & CELERY
# =============================================================================
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# =============================================================================
# JWT CONFIGURATION
# =============================================================================
JWT_ISSUER=authly-api
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_LIFETIME=15  # minutes
JWT_REFRESH_TOKEN_LIFETIME=10080  # minutes (7 days)
JWT_ROTATE_REFRESH_TOKENS=True

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
DEFAULT_FROM_EMAIL=noreply@authly.com
SUPPORT_EMAIL=support@authly.com

# For production, use SendGrid:
# EMAIL_BACKEND=anymail.backends.sendgrid.EmailBackend
# SENDGRID_API_KEY=your-sendgrid-api-key

# =============================================================================
# BILLING & STRIPE (Optional)
# =============================================================================
BILLING_ENABLED=True
STRIPE_PUBLISHABLE_KEY=pk_test_your-stripe-publishable-key
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=whsec_your-webhook-secret

# =============================================================================
# FEATURE FLAGS
# =============================================================================
FEATURE_SSO_ENABLED=True
FEATURE_MFA_ENABLED=True
FEATURE_WEBHOOKS_ENABLED=True
FEATURE_API_KEYS_ENABLED=True
FEATURE_AUDIT_LOGS_ENABLED=True
FEATURE_SCOPED_TOKENS_ENABLED=True
FEATURE_TENANT_BRANDING_ENABLED=True

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
SECURE_SSL_REDIRECT=False  # Set to True in production
CSRF_COOKIE_SECURE=False  # Set to True in production
SESSION_COOKIE_SECURE=False  # Set to True in production
```

### 6. Initialize Database

```bash
# Create and apply migrations for shared schema
python manage.py makemigrations
python manage.py migrate_schemas --shared

# Create migrations for tenant apps
python manage.py makemigrations tenants users authentication roles api_keys webhooks audit federation tokens customization billing

# Apply all migrations
python manage.py migrate_schemas
```

### 7. Create Superuser

```bash
# Create Django superuser (for public schema)
python manage.py createsuperuser
```

### 8. Create Your First Tenant

```bash
# Start Django shell
python manage.py shell
```

In the Django shell, create a tenant:

```python
from apps.tenants.models import Tenant, Domain

# Create tenant
tenant = Tenant(
    name="Demo Company",
    schema_name="demo",  # Must be lowercase, alphanumeric
    description="Demo tenant for testing"
)
tenant.save()

# Create domain for tenant
domain = Domain(
    domain="demo.localhost",  # For local development
    tenant=tenant,
    is_primary=True
)
domain.save()

print(f"Tenant created: {tenant.name} ({tenant.schema_name})")
print(f"Domain: {domain.domain}")

# Exit shell
exit()
```

### 9. Start Development Server

```bash
# Start Redis (in a separate terminal)
redis-server

# Start Celery worker (in a separate terminal)
celery -A authly_api worker --loglevel=info

# Start Django development server
python manage.py runserver
```

## 🌐 Accessing the API

Once the server is running, you can access:

### API Endpoints
- **API Root**: http://localhost:8000/api/
- **Interactive Documentation**: http://localhost:8000/api/docs/
- **OpenAPI Schema**: http://localhost:8000/api/schema/
- **Admin Interface**: http://localhost:8000/admin/

### Tenant-Specific Access
- **Demo Tenant**: http://demo.localhost:8000/api/
- **Tenant API Docs**: http://demo.localhost:8000/api/docs/

### Test API Connectivity

```bash
# Test public endpoints
curl http://localhost:8000/api/

# Test tenant endpoints (after creating demo tenant)
curl -H "Host: demo.localhost" http://localhost:8000/api/users/

# Authentication test
curl -X POST http://demo.localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "password"}'
```

## 🔧 Development Setup

### Enable Development Tools

Add to your `.env`:

```bash
# Development settings
DEV_TOOLBAR_ENABLED=True
DEBUG_LOG_SQL=False  # Set to True to see SQL queries
```

### Install Development Dependencies

```bash
# If you have a separate dev requirements file
pip install pytest pytest-django pytest-cov black isort flake8
pip install django-debug-toolbar ipython

# Add to INSTALLED_APPS in development
# 'debug_toolbar',  # Already configured in settings.py
```

### Run Tests

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test apps.users
python manage.py test apps.authentication

# Run with coverage (if pytest-cov installed)
pytest --cov=apps --cov-report=html
```

## 🐳 Docker Development

### Using Docker Compose

```bash
# Start all services
docker-compose up -d postgres redis pgadmin

# Check services
docker-compose ps

# View logs
docker-compose logs -f postgres
```

### Service Access
- **pgAdmin**: http://localhost:5050 (admin@admin.com / admin)
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 🚀 Production Deployment

### Environment Configuration

Update your `.env` for production:

```bash
# Production settings
DJANGO_DEBUG=False
DJANGO_ENVIRONMENT=production
DJANGO_ALLOWED_HOSTS=yourdomain.com,*.yourdomain.com

# Security settings
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True

# Database (use environment-specific values)
POSTGRES_HOST=your-db-host
POSTGRES_PASSWORD=your-secure-production-password

# Email (use real email service)
EMAIL_BACKEND=anymail.backends.sendgrid.EmailBackend
SENDGRID_API_KEY=your-production-sendgrid-key

# Monitoring
SENTRY_DSN=your-sentry-dsn
DATADOG_API_KEY=your-datadog-key
```

### Deploy with Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Collect static files
python manage.py collectstatic --noinput

# Run with gunicorn
gunicorn authly_api.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --timeout 30 \
    --keep-alive 2 \
    --max-requests 1000 \
    --max-requests-jitter 100
```

### Database Migration in Production

```bash
# Apply migrations (shared schema first)
python manage.py migrate_schemas --shared

# Apply to all tenant schemas
python manage.py migrate_schemas

# Create tenants via management command or API
```

## 📚 API Usage Examples

### Authentication

```bash
# Register new user (tenant-specific)
curl -X POST http://demo.localhost:8000/api/users/register/ \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "SecurePass123!",
       "first_name": "John",
       "last_name": "Doe"
     }'

# Login
curl -X POST http://demo.localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "SecurePass123!"
     }'

# Use JWT token in subsequent requests
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://demo.localhost:8000/api/users/profile/
```

### Using the Python SDK

```python
from authly_client_sdk import AuthlyClient

# Initialize client
client = AuthlyClient(
    base_url="http://demo.localhost:8000",
    api_key="your-api-key"  # Optional, can use username/password
)

# Authenticate
client.authenticate("user@example.com", "password")

# Use API methods
users = client.get_users()
profile = client.get_user_profile()
roles = client.get_roles()

# Create API key
api_key = client.create_api_key(
    name="Integration Key",
    permissions=["users.read", "roles.read"]
)

# Billing operations (if enabled)
plans = client.get_billing_plans()
subscription = client.create_subscription("professional", "monthly")
```

## 📖 API Documentation

The API provides comprehensive documentation:

### Interactive Documentation
- **Swagger UI**: http://localhost:8000/api/docs/
- **ReDoc**: http://localhost:8000/api/redoc/

### Key Endpoint Categories

- **/api/auth/** - Authentication & authorization
- **/api/users/** - User management
- **/api/roles/** - Role and permission management
- **/api/api-keys/** - API key management
- **/api/billing/** - Subscription and billing
- **/api/webhooks/** - Webhook configuration
- **/api/audit/** - Audit logs and activity
- **/api/federation/** - SSO and federation
- **/api/tokens/** - Token management
- **/api/tenants/** - Tenant management (public schema)

## 🔒 Security Features

### Authentication & Authorization
- JWT tokens with short expiration and refresh rotation
- Multi-factor authentication with TOTP
- Role-based access control with granular permissions
- API key authentication for service accounts
- Rate limiting on authentication endpoints

### Data Protection
- PostgreSQL schema-based tenant isolation
- Encrypted password storage with Django's PBKDF2
- Secure session management
- CSRF protection for web requests
- XSS protection headers

### Compliance & Audit
- Comprehensive audit logging
- GDPR-compliant data export and deletion
- SOC 2 compliance features
- Automated security headers
- Data retention policies

## 🧪 Testing

### Running Tests

```bash
# Run all tests
python manage.py test

# Run with verbose output
python manage.py test --verbosity=2

# Run specific test modules
python manage.py test apps.users.tests
python manage.py test apps.authentication.tests.test_login

# Run with coverage (if pytest installed)
pytest --cov=apps --cov-report=html --cov-report=term
```

### Test Database

Tests automatically use a separate test database. For tenant-specific tests:

```python
from django.test import TestCase
from django_tenants.test.cases import TenantTestCase
from apps.tenants.models import Tenant

class MyTenantTest(TenantTestCase):
    def setUp(self):
        self.tenant = Tenant(schema_name='test', name='Test Tenant')
        self.tenant.save()
        # Tests run in tenant context automatically
```

## 🚨 Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U authly_user -d authly_api

# Reset database (development only)
python manage.py migrate_schemas --shared
python manage.py migrate_schemas
```

#### Redis Connection Issues
```bash
# Check Redis status
redis-cli ping

# Check Redis configuration
redis-cli CONFIG GET "*"
```

#### Tenant Creation Issues
```bash
# Ensure schema_name is lowercase and alphanumeric
# Ensure domain is unique
# Check tenant exists before creating domains
```

#### Migration Issues
```bash
# Reset migrations (development only)
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete
python manage.py makemigrations
python manage.py migrate_schemas --shared
python manage.py migrate_schemas
```

### Debug Mode

Enable debug logging in `.env`:

```bash
DJANGO_DEBUG=True
DEBUG_LOG_SQL=True
LOG_LEVEL=DEBUG
```

### Performance Issues

```bash
# Check database performance
python manage.py dbshell
EXPLAIN ANALYZE SELECT * FROM your_query;

# Monitor with django-debug-toolbar
# Install and add to INSTALLED_APPS

# Check Celery tasks
celery -A authly_api inspect active
```

## 📞 Support

### Documentation
- **API Docs**: http://localhost:8000/api/docs/
- **Code Documentation**: See inline docstrings
- **Architecture**: See `CLAUDE.md` for technical details

### Getting Help
- **Issues**: Create an issue on GitHub
- **Email**: support@authly.com
- **Documentation**: Check the `/api/docs/` endpoint

### Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Django REST Framework community
- django-tenants contributors
- PostgreSQL development team
- All contributors and users

---

**Authly API** - Enterprise Identity & Access Management Platform
Built with ❤️ using Django, PostgreSQL, and modern web technologies.