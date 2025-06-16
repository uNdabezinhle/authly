# Authly Authentication System

Authly is a comprehensive authentication and authorization system built with Django REST Framework that provides user identity management, credential verification, and resource access control for enterprise-level applications.

## Features

- **Security**: Robust authentication and authorization mechanisms to protect sensitive data
- **Multiple Authentication Methods**: Local, social, 2FA, passwordless, API key, and SSO support
- **Role-Based Access Control (RBAC)**: Flexible permission system with role hierarchies
- **Attribute-Based Access Control (ABAC)**: Rule-based engine for complex authorization policies
- **OAuth2 & OpenID Connect**: Standards-compliant implementation for secure API access and authentication
- **API Key Management**: Create and manage API keys for service-to-service authentication
- **Token Management**: JWT-based secure token handling with configurable expiration policies
- **Password Management**: Password policies, secure storage, and reset functionality
- **Audit Logging**: Comprehensive logging of all authentication and authorization events
- **Customizable**: Extensive branding and customization options

## Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL (recommended) or another database supported by Django
- Virtual environment (recommended)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/undabezinhle/authly.git
   cd authly
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv authly-env
   source authly-env/bin/activate  # On Windows: authly-env\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```

5. Edit the `.env` file with your configuration settings.

6. Create the database:
   ```bash
   # For PostgreSQL
   createdb authly
   ```

7. Run migrations:
   ```bash
   python manage.py migrate
   ```

8. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

9. Create required directories:
   ```bash
   mkdir -p logs media static
   ```

10. Collect static files:
    ```bash
    python manage.py collectstatic
    ```

## Running the Server

### Development

```bash
python manage.py runserver
```

### Production

For production deployments, we recommend using Gunicorn with Nginx:

```bash
gunicorn authly.wsgi:application --bind 0.0.0.0:8000 --workers 4 --timeout 120
```

## API Documentation

Once the server is running, you can access the API documentation at:

```
http://localhost:8000/docs/
```

## Key Endpoints

### Authentication

- `POST /api/auth/login/`: User login
- `POST /api/auth/logout/`: User logout
- `POST /api/auth/register/`: Register a new user
- `POST /api/auth/password/reset/`: Request password reset
- `POST /api/auth/password/reset/confirm/`: Confirm password reset
- `POST /api/auth/2fa/enable/`: Enable two-factor authentication
- `POST /api/auth/2fa/disable/`: Disable two-factor authentication
- `POST /api/auth/2fa/verify/`: Verify two-factor authentication code
- `GET /api/auth/session/`: Check session validity
- `POST /api/auth/refresh/`: Refresh access token

### User Management

- `GET /api/users/`: List users
- `POST /api/users/`: Create a new user
- `GET /api/users/{id}/`: Get user details
- `PUT /api/users/{id}/`: Update a user
- `DELETE /api/users/{id}/`: Delete a user

### Role Management

- `GET /api/roles/roles/`: List roles
- `POST /api/roles/roles/`: Create a new role
- `GET /api/roles/roles/{id}/`: Get role details
- `PUT /api/roles/roles/{id}/`: Update a role
- `DELETE /api/roles/roles/{id}/`: Delete a role
- `GET /api/roles/roles/{id}/permissions/`: Get role permissions
- `POST /api/roles/roles/{id}/add_permissions/`: Add permissions to a role
- `POST /api/roles/roles/{id}/remove_permissions/`: Remove permissions from a role

### API Key Management

- `GET /api/api-keys/`: List API keys
- `POST /api/api-keys/`: Create a new API key
- `GET /api/api-keys/{id}/`: Get API key details
- `DELETE /api/api-keys/{id}/`: Delete an API key
- `POST /api/api-keys/{id}/revoke/`: Revoke an API key

### OAuth2

- `GET /api/oauth2/authorize/`: OAuth2 authorization endpoint
- `POST /api/oauth2/token/`: OAuth2 token endpoint
- `GET /api/oauth2/userinfo/`: OpenID Connect userinfo endpoint
- `GET /api/oauth2/.well-known/jwks.json`: JSON Web Key Set endpoint


# SSO and Active Directory Integration for Authly

## Overview

Authly now includes comprehensive Single Sign-On (SSO) and Active Directory integration capabilities, allowing enterprises to leverage their existing identity infrastructure. The following protocols are supported:

- **SAML 2.0**: Industry standard for web-based authentication and authorization
- **OpenID Connect (OIDC)**: Modern identity layer on top of OAuth 2.0
- **LDAP/Active Directory**: Traditional enterprise directory services
- **OAuth 2.0**: For integration with other OAuth 2.0 providers

## Features

- **Multiple Identity Providers**: Configure and manage multiple IdPs simultaneously
- **User Mapping**: Automatic mapping between external identities and local users
- **Just-in-time Provisioning**: Automatically create users when they first authenticate via SSO
- **Session Management**: Track and manage SSO sessions
- **Attribute Mapping**: Customizable mapping of IdP attributes to user properties
- **Role Mapping**: Map IdP groups/roles to local roles (coming soon)

## Configuration

### SAML 2.0

To configure a SAML 2.0 identity provider:

1. Create a new `IdentityProvider` with protocol `saml`
2. Configure the following in the `config` JSON field:
   ```json
   {
     "service_provider": {
       "entity_id": "https://your-authly-domain/api/sso/saml/metadata/",
       "acs_url": "https://your-authly-domain/api/sso/callback/PROVIDER_ID/",
       "sls_url": "https://your-authly-domain/api/sso/logout/PROVIDER_ID/",
       "x509cert": "YOUR_SP_CERTIFICATE",
       "private_key": "YOUR_SP_PRIVATE_KEY"
     },
     "identity_provider": {
       "entity_id": "https://idp.example.com/metadata",
       "sso_url": "https://idp.example.com/sso",
       "slo_url": "https://idp.example.com/slo",
       "x509cert": "IDP_CERTIFICATE"
     },
     "attribute_mapping": {
       "email": "email",
       "first_name": "firstName",
       "last_name": "lastName",
       "username": "userName"
     }
   }
   ```
3. Replace `PROVIDER_ID` with the UUID of the created provider

### LDAP/Active Directory

To configure LDAP/Active Directory:

1. Create a new `IdentityProvider` with protocol `ldap`
2. Configure the following in the `config` JSON field:
   ```json
   {
     "server_uri": "ldap://ad.example.com",
     "bind_dn": "CN=ServiceAccount,OU=ServiceAccounts,DC=example,DC=com",
     "bind_password": "ServiceAccountPassword",
     "base_dn": "DC=example,DC=com",
     "search_filter": "(sAMAccountName={username})",
     "attributes": ["mail", "givenName", "sn", "displayName", "objectGUID", "sAMAccountName"],
     "email_attribute": "mail",
     "id_attribute": "objectGUID",
     "use_tls": true,
     "default_domain": "example.com"
   }
   ```

### OpenID Connect

To configure an OpenID Connect provider:

1. Create a new `IdentityProvider` with protocol `oidc`
2. Configure the following in the `config` JSON field:
   ```json
   {
     "client_id": "your-client-id",
     "client_secret": "your-client-secret",
     "authorization_endpoint": "https://idp.example.com/auth",
     "token_endpoint": "https://idp.example.com/token",
     "userinfo_endpoint": "https://idp.example.com/userinfo",
     "redirect_uri": "https://your-authly-domain/api/sso/callback/PROVIDER_ID/",
     "scope": "openid email profile",
     "field_mapping": {
       "first_name": "given_name",
       "last_name": "family_name",
       "name": "name",
       "username": "preferred_username"
     }
   }
   ```
3. Replace `PROVIDER_ID` with the UUID of the created provider

## API Endpoints

### Management Endpoints

- `GET /api/sso/providers/`: List all identity providers
- `POST /api/sso/providers/`: Create a new identity provider
- `GET /api/sso/providers/{id}/`: Get a specific identity provider
- `PUT/PATCH /api/sso/providers/{id}/`: Update a identity provider
- `DELETE /api/sso/providers/{id}/`: Delete a identity provider
- `GET /api/sso/providers/enabled/`: List all enabled identity providers
- `POST /api/sso/providers/{id}/toggle_active/`: Enable/disable a provider
- `GET /api/sso/mappings/`: List all user mappings
- `GET /api/sso/sessions/`: List all SSO sessions
- `POST /api/sso/sessions/{id}/revoke/`: Revoke a session
- `POST /api/sso/sessions/revoke_all/`: Revoke all sessions

### Authentication Endpoints

- `POST /api/sso/login/init/`: Initiate SSO login flow
- `POST /api/sso/login/ldap/`: LDAP/AD direct login
- `GET/POST /api/sso/callback/{provider_id}/`: SSO callback handler
- `POST /api/sso/callback/api/`: API-based SSO callback

## Required Dependencies

- `python-ldap`: For LDAP/Active Directory integration
- `python3-saml`: For SAML 2.0 integration
- `jwt`: For JWT token handling
- `requests`: For HTTP requests to IdPs

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LDAP_SERVER_URI` | LDAP server URI | `ldap://ldap.example.com` |
| `LDAP_BIND_DN` | LDAP bind DN | `''` |
| `LDAP_BIND_PASSWORD` | LDAP bind password | `''` |
| `LDAP_USER_SEARCH_BASE` | LDAP user search base | `ou=users,dc=example,dc=com` |
| `LDAP_GROUP_SEARCH_BASE` | LDAP group search base | `ou=groups,dc=example,dc=com` |
| `LDAP_USE_TLS` | Enable TLS for LDAP | `False` |
| `SSO_SESSION_DURATION` | SSO session duration in seconds | `43200` (12 hours) |
| `SSO_ALLOWED_REDIRECT_DOMAINS` | Comma-separated domains allowed for redirects | `localhost,127.0.0.1` |
| `SSO_DEFAULT_REDIRECT_URL` | Default URL to redirect after successful SSO | `/` |
| `SSO_ERROR_REDIRECT_URL` | URL to redirect on SSO error | `/login` |

## Security Considerations

- Store all credentials and certificates securely using environment variables or a secure key vault
- Always enable TLS for LDAP connections in production
- Validate and restrict redirect URLs to prevent open redirect vulnerabilities
- Always validate SAML responses and JWT tokens properly
- Use HTTPS for all communications with identity providers
- Monitor and audit SSO activity regularly

## Security Considerations

- Always use HTTPS in production
- Regular security audits and updates
- Follow the principle of least privilege
- Keep dependencies updated
- Implement rate limiting for sensitive endpoints

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.#   a u t h l y 
 
 