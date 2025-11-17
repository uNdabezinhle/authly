# Authly Python SDK

🚀 **Enterprise-grade Python SDK** for the Authly Identity & Access Management platform.

## 🌟 Enterprise Features

### 🔐 **Complete Authentication & Identity**
- **User Lifecycle**: Registration, activation, login, MFA, password management
- **Session Management**: Automatic token refresh, persistence, and cleanup
- **Multi-Factor Auth**: TOTP-based 2FA with QR codes and backup codes
- **Password Security**: Secure reset flows and policy enforcement

### 👥 **Identity Federation & SSO**
- **SAML Integration**: Configure SAML identity providers
- **OIDC/OAuth2**: Modern federation standards support
- **SSO Management**: Single sign-on configuration and testing
- **Federation Mapping**: Attribute and role mapping configuration

### 🔑 **Advanced Token & API Management**
- **Scoped Tokens**: Fine-grained API access control
- **API Key Lifecycle**: Creation, rotation, and revocation
- **Token Analytics**: Usage tracking and security monitoring
- **Service Accounts**: Machine-to-machine authentication

### 💳 **Enterprise Billing & Subscriptions**
- **Subscription Management**: Plan creation, upgrades, downgrades
- **Usage Tracking**: Metered billing and quota management
- **Invoice Management**: Automated billing and payment processing
- **Billing Analytics**: Usage reports and cost optimization

### 🎨 **Tenant Customization & Branding**
- **Custom Themes**: Brand colors, logos, and styling
- **Domain Configuration**: Custom domain setup and SSL
- **Email Templates**: Branded communication templates
- **Onboarding Flows**: Custom user onboarding experiences

### 📊 **Analytics & Compliance**
- **Audit Analytics**: Security events and user activity
- **Compliance Reports**: SOC2, GDPR, HIPAA reporting
- **Data Export**: GDPR-compliant data portability
- **Risk Analytics**: Behavioral analysis and threat detection

### 🔄 **Enterprise Integration**
- **Webhook Management**: Real-time event notifications
- **Data Synchronization**: User and role synchronization
- **Bulk Operations**: Mass user import/export capabilities
- **API Orchestration**: Complex workflow automation

### 🛡️ **Advanced Security**
- **Role Delegation**: Temporary privilege escalation
- **Session Security**: Advanced session management
- **Security Analytics**: Threat detection and monitoring
- **Compliance Automation**: Policy enforcement and reporting

## Quick Start

### Installation

```python
pip install requests urllib3
```

### Basic Usage

```python
from authly_client_sdk import AuthlyClient

# Initialize client
client = AuthlyClient(
    base_url="https://api.authly.com",
    tenant="your-tenant"
)

# Register new user
result = client.register(
    email="user@example.com",
    password="SecurePassword123!",
    first_name="John",
    last_name="Doe"
)

# Login and get tokens
tokens = client.login("user@example.com", "SecurePassword123!")

# All subsequent requests are automatically authenticated
profile = client.get_profile()
permissions = client.get_my_permissions()

# Upload avatar
profile = client.upload_avatar("/path/to/image.jpg")

# Create API key
api_key = client.create_api_key(
    name="My Application",
    expires_at="2024-12-31T23:59:59"
)
```

### Context Manager

```python
# Recommended: Use context manager for automatic cleanup
with AuthlyClient(base_url="https://api.authly.com", tenant="your-tenant") as client:
    client.login("user@example.com", "password")
    profile = client.get_profile()
    # Session automatically cleaned up
```

## Authentication Methods

### User Registration

```python
result = client.register(
    email="user@example.com",
    password="SecurePassword123!",
    first_name="John",
    last_name="Doe",
    phone="+1-555-0123",  # Optional
    bio="Software Engineer",  # Optional
    privacy_profile_visible=True,
    privacy_email_visible=False
)
print(f"Registration: {result['message']}")
```

### Account Activation

```python
# From activation email
result = client.activate(uid="user-uid", token="activation-token")
print(f"Activation: {result['message']}")
```

### Login & Authentication

```python
# Basic login
tokens = client.login("user@example.com", "password")

# Login with MFA
try:
    tokens = client.login("user@example.com", "password")
except MFARequiredError:
    mfa_token = input("Enter MFA token: ")
    tokens = client.login("user@example.com", "password", mfa_token)

print(f"Welcome {tokens['user']['first_name']}!")
```

### Password Management

```python
# Forgot password
result = client.forgot_password("user@example.com")

# Reset password (from email link)
result = client.reset_password(
    uid="user-uid", 
    token="reset-token", 
    new_password="NewSecurePassword123!"
)

# Change password (authenticated)
result = client.change_password(
    old_password="current_password",
    new_password="new_password"
)
```

## Multi-Factor Authentication (MFA)

```python
# Enable MFA
mfa_data = client.mfa_enable()
print(f"QR Code: {mfa_data['qr_code_url']}")
print(f"Manual Key: {mfa_data['manual_key']}")

# Verify setup with TOTP token
result = client.mfa_verify("123456")

# Check MFA status
status = client.mfa_status()
print(f"MFA Enabled: {status['mfa_enabled']}")

# Disable MFA
result = client.mfa_disable("current_password")
```

## Profile Management

```python
# Get current profile
profile = client.get_profile()
print(f"User: {profile['first_name']} {profile['last_name']}")

# Update profile
updated = client.update_profile(
    first_name="Jane",
    bio="Updated bio text",
    privacy_phone_visible=True
)

# Upload avatar image
profile = client.upload_avatar("/path/to/avatar.jpg")
print(f"Avatar URL: {profile['avatar']}")
```

## Authorization & Permissions

```python
# Get all user permissions
permissions = client.get_my_permissions()
print(f"You have {len(permissions)} permissions")

# Check specific permission
if client.has_permission("users.manage_users"):
    print("You can manage users!")
else:
    print("Access denied")

# Permission examples
permission_checks = [
    "users.view_profile",
    "users.change_profile", 
    "api_keys.create_own",
    "roles.manage_roles"
]

for perm in permission_checks:
    has_perm = client.has_permission(perm)
    print(f"{perm}: {'✅' if has_perm else '❌'}")
```

## API Key Management

```python
# Create API key
api_key = client.create_api_key(
    name="Production App",
    scopes=["read", "write"],  # Optional
    expires_at="2024-12-31T23:59:59"  # Optional
)

print(f"API Key: {api_key['key']}")  # Only shown once!
print(f"Key ID: {api_key['id']}")

# List API keys
keys = client.list_api_keys()
for key in keys:
    print(f"Key: {key['name']} (expires: {key['expires_at']})")

# Revoke API key
client.revoke_api_key(api_key['id'])
```

## Advanced Features

### Session Persistence

```python
# Tokens automatically saved to ~/.authly_session.json
client = AuthlyClient("https://api.authly.com", "tenant")
client.login("user@example.com", "password")

# Later... tokens automatically restored
client2 = AuthlyClient("https://api.authly.com", "tenant")
if client2.is_authenticated():
    profile = client2.get_profile()  # Works without re-login!
```

### Custom Session Storage

```python
client = AuthlyClient(
    base_url="https://api.authly.com",
    tenant="your-tenant",
    session_file="/custom/path/to/session.json"
)
```

### API Key Authentication

```python
# Use API key instead of user tokens
client = AuthlyClient(
    base_url="https://api.authly.com",
    tenant="your-tenant",
    api_key="your-api-key-here"
)

# All requests use API key authentication
profile = client.get_profile()
```

### Configuration Options

```python
client = AuthlyClient(
    base_url="https://api.authly.com",
    tenant="your-tenant",
    timeout=30,              # Request timeout (seconds)
    max_retries=3,           # Retry attempts
    verify_ssl=True,         # SSL verification
    debug=True,              # Enable debug logging
    session_file="/custom/path/session.json"
)
```

## Error Handling

```python
from authly_client_sdk import (
    AuthlyError,
    AuthenticationError,
    AuthorizationError, 
    MFARequiredError,
    ValidationError,
    NetworkError,
    RateLimitError
)

try:
    client.login("user@example.com", "wrong_password")
except AuthenticationError as e:
    print(f"Login failed: {e}")
    print(f"Status code: {e.status_code}")
    
except MFARequiredError:
    print("Please provide MFA token")
    
except ValidationError as e:
    print(f"Validation error: {e}")
    print(f"Details: {e.response_data}")
    
except NetworkError as e:
    print(f"Network error: {e}")
    
except RateLimitError:
    print("Rate limit exceeded, please wait")
    
except AuthlyError as e:
    print(f"Authly error: {e}")
```

## Multi-Tenant Support

```python
# Initialize with tenant
client = AuthlyClient("https://api.authly.com", tenant="company-a")

# Switch tenant
client.set_tenant("company-b")

# All requests now use company-b tenant
profile = client.get_profile()
```

## Testing

### Unit Tests

```bash
python test_authly_sdk.py --unit
```

### Interactive Tests

```bash
# Test against local API
python test_authly_sdk.py --interactive --url http://localhost:8000 --tenant test

# Test against production
python test_authly_sdk.py --interactive --url https://api.authly.com --tenant your-tenant
```

### Example Test Script

```python
#!/usr/bin/env python3
import sys
from authly_client_sdk import AuthlyClient

def test_workflow():
    client = AuthlyClient("http://localhost:8000", "test")
    
    # Register
    result = client.register(
        email="test@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User"
    )
    print(f"✅ Registered: {result['user_id']}")
    
    # Login
    tokens = client.login("test@example.com", "TestPass123!")
    print(f"✅ Logged in: {tokens['user']['email']}")
    
    # Get profile
    profile = client.get_profile()
    print(f"✅ Profile: {profile['first_name']} {profile['last_name']}")
    
    # Check permissions
    permissions = client.get_my_permissions()
    print(f"✅ Permissions: {len(permissions)} granted")

if __name__ == "__main__":
    test_workflow()
```

## Requirements

- **Python**: 3.8+ (3.10+ recommended)
- **Dependencies**: `requests`, `urllib3`
- **Optional**: For development - `pytest`, `black`, `mypy`

```bash
pip install -r requirements_sdk.txt
```

## Security Best Practices

1. **HTTPS Only**: Always use HTTPS in production
2. **Secure Storage**: Session files have 600 permissions
3. **Token Rotation**: Automatic JWT refresh
4. **Input Validation**: All inputs are validated
5. **Error Handling**: Secure error messages
6. **Rate Limiting**: Built-in retry with backoff

## API Reference

### Client Methods

| Method | Description | Auth Required |
|--------|-------------|---------------|
| `register()` | Register new user | No |
| `activate()` | Activate account | No |
| `login()` | User authentication | No |
| `logout()` | Logout and revoke tokens | Yes |
| `refresh_token()` | Refresh access token | No |
| `forgot_password()` | Request password reset | No |
| `reset_password()` | Reset password with token | No |
| `mfa_enable()` | Enable MFA | Yes |
| `mfa_verify()` | Verify MFA token | Yes |
| `mfa_disable()` | Disable MFA | Yes |
| `mfa_status()` | Get MFA status | Yes |
| `get_profile()` | Get user profile | Yes |
| `update_profile()` | Update profile | Yes |
| `change_password()` | Change password | Yes |
| `upload_avatar()` | Upload avatar image | Yes |
| `get_my_permissions()` | Get user permissions | Yes |
| `has_permission()` | Check permission | Yes |
| `create_api_key()` | Create API key | Yes |
| `list_api_keys()` | List API keys | Yes |
| `revoke_api_key()` | Revoke API key | Yes |

### Exception Hierarchy

```
AuthlyError (base)
├── AuthenticationError
├── AuthorizationError  
├── MFARequiredError
├── ValidationError
├── NetworkError
├── RateLimitError
└── TenantError
```

## 🏢 Enterprise Features Documentation

### Identity Federation & SSO

```python
# Configure SAML Identity Provider
saml_config = client.configure_saml_idp(
    name="Corporate ADFS",
    entity_id="https://corp.example.com/adfs",
    sso_url="https://corp.example.com/adfs/ls",
    certificate="-----BEGIN CERTIFICATE-----\n...",
    attribute_mapping={
        'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'first_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        'last_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
    }
)

# Test SAML configuration
test_result = client.test_saml_config("saml-config-id")
print(f"SAML Test: {test_result['status']}")

# Configure OIDC Provider
oidc_config = client.configure_oidc_provider(
    name="Google Workspace",
    issuer="https://accounts.google.com",
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
    scopes=['openid', 'email', 'profile']
)

# Test SSO login flow
sso_url = client.initiate_sso_login(provider_id="google-oidc")
print(f"SSO Login URL: {sso_url}")
```

### Advanced Token Management

```python
# Create scoped token for API access
scoped_token = client.create_scoped_token(
    scopes=['users.read', 'roles.read', 'audit.read'],
    audience='reporting-service',
    expires_in=3600  # 1 hour
)

print(f"Scoped Token: {scoped_token['access_token']}")
print(f"Allowed Scopes: {scoped_token['scopes']}")

# Get token analytics
analytics = client.get_token_analytics(
    start_date='2024-01-01',
    end_date='2024-01-31',
    token_type='api_key'
)

print(f"Token Usage: {analytics['total_requests']} requests")
print(f"Most Active Token: {analytics['top_tokens'][0]['name']}")

# Rotate API key
new_key = client.rotate_api_key(api_key_id="key-id-123")
print(f"New API Key: {new_key['key']}")
```

### Enterprise Billing Management

```python
# Get available billing plans
plans = client.get_billing_plans()
for plan in plans:
    print(f"Plan: {plan['name']} - ${plan['monthly_price']}/month")

# Create subscription
subscription = client.create_subscription(
    plan_id='professional',
    billing_interval='monthly'
)
print(f"Subscription ID: {subscription['id']}")

# Track usage metrics
client.track_usage(
    metric_name='api_calls',
    value=1500,
    timestamp='2024-01-15T10:30:00Z'
)

# Get billing analytics
billing_data = client.get_billing_analytics(
    start_date='2024-01-01',
    end_date='2024-01-31'
)

print(f"Current Usage: {billing_data['current_usage']}")
print(f"Projected Cost: ${billing_data['projected_monthly_cost']}")

# Download invoice
invoice_pdf = client.download_invoice(invoice_id="inv-123")
with open("invoice.pdf", "wb") as f:
    f.write(invoice_pdf)
```

### Tenant Customization & Branding

```python
# Update tenant branding
branding = client.update_tenant_branding(
    primary_color="#1a73e8",
    secondary_color="#34a853",
    logo_url="https://cdn.example.com/logo.png",
    company_name="Acme Corporation",
    support_email="help@acme.com"
)

# Configure custom domain
domain_config = client.configure_custom_domain(
    domain="auth.acme.com",
    ssl_certificate="-----BEGIN CERTIFICATE-----\n...",
    ssl_private_key="-----BEGIN PRIVATE KEY-----\n..."
)

# Update email templates
template = client.update_email_template(
    template_type="welcome",
    subject="Welcome to {{company_name}}!",
    html_content="<h1>Welcome {{user.first_name}}!</h1>...",
    text_content="Welcome {{user.first_name}}!..."
)

# Configure onboarding flow
onboarding = client.configure_onboarding(
    steps=[
        {"type": "profile_completion", "required": True},
        {"type": "mfa_setup", "required": False},
        {"type": "terms_acceptance", "required": True}
    ],
    welcome_message="Welcome to our platform!"
)
```

### Analytics & Compliance

```python
# Get audit analytics
audit_data = client.get_audit_analytics(
    start_date='2024-01-01',
    end_date='2024-01-31',
    event_types=['login', 'logout', 'password_change', 'mfa_enable']
)

print(f"Total Events: {audit_data['total_events']}")
print(f"Failed Logins: {audit_data['failed_logins']}")
print(f"Security Events: {audit_data['security_events']}")

# Generate compliance report
compliance_report = client.generate_compliance_report(
    framework='SOC2',
    start_date='2024-01-01',
    end_date='2024-03-31',
    include_evidence=True
)

print(f"Compliance Score: {compliance_report['score']}%")
print(f"Report URL: {compliance_report['download_url']}")

# Export user data (GDPR)
user_data = client.export_user_data(
    user_id="user-123",
    format="json",
    include_audit_logs=True
)

# Get risk analytics
risk_data = client.get_risk_analytics(period='30d')
print(f"Risk Score: {risk_data['overall_risk_score']}")
print(f"High Risk Users: {len(risk_data['high_risk_users'])}")
```

### Enterprise Integration & Automation

```python
# Configure webhook endpoint
webhook = client.create_webhook(
    url="https://api.yourapp.com/webhooks/authly",
    events=['user.created', 'user.login', 'user.mfa_enabled'],
    secret="webhook-signing-secret",
    active=True
)

# Sync users from external system
sync_result = client.sync_users(
    source="active_directory",
    users=[
        {
            "email": "john.doe@company.com",
            "first_name": "John",
            "last_name": "Doe",
            "department": "Engineering",
            "roles": ["developer", "team_lead"]
        }
    ],
    update_existing=True
)

print(f"Users Synced: {sync_result['created']} created, {sync_result['updated']} updated")

# Bulk export users
export_job = client.bulk_export_users(
    format="csv",
    filters={
        "department": "Engineering",
        "last_login_after": "2024-01-01"
    }
)

# Monitor export progress
status = client.get_export_status(export_job['job_id'])
if status['status'] == 'completed':
    download_url = status['download_url']
    print(f"Export ready: {download_url}")
```

### Advanced Security Features

```python
# Delegate role temporarily
delegation = client.delegate_role(
    user_id="user-123",
    role="admin",
    duration_hours=24,
    reason="Emergency system maintenance",
    require_approval=True
)

# Monitor delegated permissions
delegations = client.get_active_delegations()
for d in delegations:
    print(f"User {d['user_email']} has {d['role']} until {d['expires_at']}")

# Get security analytics
security_data = client.get_security_analytics(period='7d')
print(f"Failed Login Attempts: {security_data['failed_logins']}")
print(f"Suspicious Activity: {security_data['suspicious_events']}")
print(f"Geographic Anomalies: {security_data['geo_anomalies']}")

# Configure security policies
policy = client.configure_security_policy(
    max_failed_attempts=5,
    lockout_duration_minutes=30,
    password_policy={
        "min_length": 12,
        "require_uppercase": True,
        "require_numbers": True,
        "require_symbols": True
    },
    session_timeout_minutes=480  # 8 hours
)
```

### Comprehensive API Reference

#### Enterprise Authentication Methods

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `configure_saml_idp()` | Setup SAML identity provider | name, entity_id, sso_url, certificate, mappings | Configuration object |
| `configure_oidc_provider()` | Setup OIDC provider | name, issuer, client_id, client_secret, scopes | Configuration object |
| `test_saml_config()` | Test SAML configuration | config_id | Test results |
| `initiate_sso_login()` | Start SSO login flow | provider_id, redirect_url | SSO login URL |

#### Token & API Management

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `create_scoped_token()` | Create limited-scope token | scopes, audience, expires_in | Token with metadata |
| `get_token_analytics()` | Token usage analytics | start_date, end_date, token_type | Usage statistics |
| `rotate_api_key()` | Rotate existing API key | api_key_id | New API key |
| `revoke_all_tokens()` | Revoke all user tokens | user_id, reason | Revocation status |

#### Billing & Subscriptions

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `get_billing_plans()` | List available plans | None | Array of plans |
| `create_subscription()` | Create new subscription | plan_id, billing_interval | Subscription object |
| `track_usage()` | Record usage metrics | metric_name, value, timestamp | Tracking result |
| `get_billing_analytics()` | Usage and cost analytics | start_date, end_date | Billing data |
| `download_invoice()` | Get invoice PDF | invoice_id | PDF binary data |

#### Tenant Customization

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `update_tenant_branding()` | Update visual branding | colors, logo, company_name, etc. | Branding config |
| `configure_custom_domain()` | Setup custom domain | domain, ssl_cert, ssl_key | Domain config |
| `update_email_template()` | Customize email templates | type, subject, html, text | Template config |
| `configure_onboarding()` | Setup onboarding flow | steps, welcome_message | Onboarding config |

#### Analytics & Compliance

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `get_audit_analytics()` | Audit event analytics | start_date, end_date, event_types | Analytics data |
| `generate_compliance_report()` | Generate compliance report | framework, date_range, options | Report object |
| `export_user_data()` | GDPR data export | user_id, format, include_logs | User data export |
| `get_risk_analytics()` | Security risk analysis | period | Risk assessment |

#### Integration & Automation

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `create_webhook()` | Configure webhook endpoint | url, events, secret, active | Webhook config |
| `sync_users()` | Bulk user synchronization | source, users, options | Sync results |
| `bulk_export_users()` | Export users in bulk | format, filters | Export job |
| `get_export_status()` | Check export job status | job_id | Status and download URL |

#### Advanced Security

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| `delegate_role()` | Temporary role delegation | user_id, role, duration, reason | Delegation object |
| `get_active_delegations()` | List active delegations | None | Array of delegations |
| `get_security_analytics()` | Security event analytics | period | Security metrics |
| `configure_security_policy()` | Update security policies | policy_settings | Policy config |

## Demo Script

Run the included demo for a complete workflow example:

```bash
python authly_client_sdk.py demo
```

## Enterprise Demo

For enterprise features demonstration:

```bash
python authly_client_sdk.py enterprise-demo
```

## License

MIT License - see LICENSE file for details.

## Support

- **Documentation**: Full API docs at your Authly instance `/api/docs/`
- **Enterprise Support**: enterprise@authly.com
- **Issues**: Report issues on GitHub  
- **Examples**: See `test_authly_sdk.py` for comprehensive examples

---

**🏢 Enterprise ready • 🔒 Security focused • 🚀 Production proven**