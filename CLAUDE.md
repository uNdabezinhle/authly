# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authly API is a multi-tenant Django REST API for Enterprise Identity & Access Management. It provides authentication, authorization, user management, and audit capabilities using a tenant-isolated architecture with PostgreSQL schemas.

## Architecture

### Backend (Django)
- **Framework**: Django with Django REST Framework
- **Multi-tenancy**: django-tenants with PostgreSQL schema isolation
- **Database**: PostgreSQL with tenant-specific schemas
- **Authentication**: JWT-based authentication using SimpleJWT
- **API Documentation**: drf-spectacular (OpenAPI/Swagger)
- **Background Tasks**: Celery with Redis
- **File Storage**: Local filesystem (avatars in media/)

### Multi-Tenant Architecture
- **Tenant Model**: Each tenant gets its own PostgreSQL schema
- **Shared Apps**: Core system apps (tenants, auth, admin) live in public schema
- **Tenant Apps**: Business logic apps (users, roles, api_keys, etc.) live in tenant schemas
- **Domain Routing**: Subdomains route to specific tenant schemas
- **Schema Isolation**: Complete data separation between tenants

### Core Applications
- `tenants` - Multi-tenant management (shared schema)
- `users` - User management with profiles and privacy settings
- `authentication` - JWT authentication endpoints
- `roles` - Role-based access control
- `api_keys` - API key management for programmatic access
- `webhooks` - Webhook configuration and delivery
- `audit` - Audit logging and activity tracking

### Database Architecture
- PostgreSQL with schema-per-tenant isolation
- Custom User model extending AbstractUser with tenant association
- Privacy controls for user profile data
- Avatar file management with automatic cleanup
- Audit trails for security and compliance

## Development Commands

### Environment Setup
```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows

# Install dependencies (no requirements files found - use pip install)
pip install django djangorestframework django-tenants djangorestframework-simplejwt
pip install drf-spectacular celery redis python-decouple pillow
```

### Database Commands
```bash
# Create and apply migrations
python manage.py makemigrations
python manage.py migrate_schemas --shared  # Migrate shared schema
python manage.py migrate_schemas  # Migrate all tenant schemas

# Create superuser (in public schema)
python manage.py createsuperuser

# Create tenant
python manage.py shell
# In shell: create Tenant and Domain objects
```

### Development Server
```bash
# Run development server
python manage.py runserver

# Access API documentation
# http://localhost:8000/api/docs/  - Swagger UI
# http://localhost:8000/api/schema/  - OpenAPI schema
```

### Testing Commands
```bash
# Run tests (using Django's built-in test framework)
python manage.py test

# Run tests for specific app
python manage.py test apps.users

# Run tests for specific test case
python manage.py test apps.users.tests.TestClassName
```

### Docker Development
```bash
# Start supporting services (PostgreSQL, pgAdmin, email)
docker compose up -d postgres pgadmin greenmail rainloop

# Database access via pgAdmin: http://localhost:5050
# Email testing via RainLoop: http://localhost:8081
# GreenMail SMTP: localhost:3025
```

## Settings Configuration

The project uses python-decouple for environment variable management:

### Required Environment Variables (.env file)
```bash
DJANGO_SECRET_KEY=your-secret-key
DJANGO_DEBUG=True
POSTGRES_DB=authly_api
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
REDIS_URL=redis://localhost:6379/0
```

## API Endpoints

### Core API Structure
- `/api/tenants/` - Tenant management
- `/api/users/` - User management
- `/api/auth/` - Authentication (login, refresh, etc.)
- `/api/roles/` - Role and permission management
- `/api/api-keys/` - API key management
- `/api/webhooks/` - Webhook configuration
- `/api/audit/` - Audit log access
- `/api/docs/` - Interactive API documentation
- `/api/schema/` - OpenAPI schema

## Key Implementation Notes

### Multi-Tenant Patterns
- All tenant-specific models are isolated in separate PostgreSQL schemas
- Middleware handles tenant resolution from subdomain
- Shared models (Tenant, Domain) live in public schema
- Custom management commands support schema-specific operations

### Authentication & Security
- JWT tokens with 15-minute access and 7-day refresh lifetime
- Token rotation enabled for enhanced security
- Custom User model with tenant association
- Privacy controls for user profile data visibility
- MFA support framework (not yet implemented)

### API Design
- RESTful endpoints with consistent naming
- Comprehensive API documentation via drf-spectacular
- Pagination enabled (20 items per page default)
- JWT authentication required for all endpoints

### File Management
- Avatar uploads stored in `media/avatars/`
- Automatic file cleanup when users are deleted
- Local filesystem storage (configurable for cloud storage)

## Development Status

The project has a complete multi-tenant foundation with:
- Multi-tenant infrastructure fully implemented
- User management with profiles and privacy controls
- JWT authentication system
- Role-based access control framework
- API key management for service accounts
- Webhook system for event notifications
- Audit logging capabilities
- Comprehensive API documentation

Most apps have basic model structures but may need additional business logic implementation. The tenant isolation architecture is production-ready.

## Important Notes

- Always use `migrate_schemas` instead of `migrate` for tenant-aware migrations
- Create tenants via Django shell or admin interface before testing tenant-specific functionality
- Use tenant-specific subdomains for API access in multi-tenant mode
- All user data is tenant-isolated automatically via schema separation