#!/usr/bin/env python3
"""
Authly Client SDK - Production-grade Python SDK for Authly API
Enterprise Identity & Access Management Multi-tenant Service

Author: Authly Team
Version: 2.0.0 - Enterprise Edition
License: MIT

NEW ENTERPRISE FEATURES:
- Identity Federation (SAML/OIDC)
- Scoped Token Management
- Billing & Subscription Management
- Multi-tenant Customization
- Audit Analytics & Security Monitoring
- Data Export & Compliance Tools
- Advanced Role Delegation (RBAC/ABAC)

Example Usage:
    from authly_client_sdk import AuthlyClient
    
    # Initialize client
    client = AuthlyClient(
        base_url="https://api.authly.com",
        tenant="your-tenant",
        timeout=30
    )
    
    # Enterprise Features
    
    # 1. SSO Configuration
    client.configure_sso(
        provider_type="saml",
        entity_id="https://idp.company.com",
        sso_url="https://idp.company.com/sso"
    )
    
    # 2. Scoped Token Management
    token = client.create_scoped_token(
        scopes=["users.read", "audit.read"],
        audience="api.company.com"
    )
    
    # 3. Billing Management
    client.create_subscription(
        plan_id="professional",
        billing_interval="monthly"
    )
    usage = client.get_usage_metrics()
    
    # 4. Data Export
    export = client.export_data(
        export_type="compliance",
        format="encrypted"
    )
    
    # 5. Audit Analytics
    threats = client.get_security_alerts()
    analytics = client.get_audit_analytics()
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, BinaryIO
from urllib.parse import urljoin, urlparse
import base64
import hashlib
import hmac

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)


class AuthlyError(Exception):
    """Base exception for all Authly SDK errors"""
    
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 response_data: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class AuthenticationError(AuthlyError):
    """Authentication failed"""
    pass


class AuthorizationError(AuthlyError):
    """Authorization/permission denied"""
    pass


class MFARequiredError(AuthlyError):
    """MFA token required for authentication"""
    
    def __init__(self, message: str = "MFA token required", **kwargs):
        super().__init__(message, **kwargs)


class ValidationError(AuthlyError):
    """Request validation failed"""
    pass


class NetworkError(AuthlyError):
    """Network/connection error"""
    pass


class RateLimitError(AuthlyError):
    """Rate limit exceeded"""
    pass


class TenantError(AuthlyError):
    """Tenant-related error"""
    pass


class SessionManager:
    """Manages JWT tokens and session persistence"""
    
    def __init__(self, session_file: Optional[str] = None):
        self.session_file = session_file or os.path.expanduser("~/.authly_session.json")
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self._load_session()
    
    def _load_session(self) -> None:
        """Load session from file if exists"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r') as f:
                    data = json.load(f)
                    self.access_token = data.get('access_token')
                    self.refresh_token = data.get('refresh_token')
                    expires_str = data.get('expires_at')
                    if expires_str:
                        self.token_expires_at = datetime.fromisoformat(expires_str)
        except Exception as e:
            logger.debug(f"Failed to load session: {e}")
    
    def save_session(self) -> None:
        """Save current session to file"""
        try:
            os.makedirs(os.path.dirname(self.session_file), exist_ok=True)
            data = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None
            }
            with open(self.session_file, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(self.session_file, 0o600)  # Secure permissions
        except Exception as e:
            logger.warning(f"Failed to save session: {e}")
    
    def clear_session(self) -> None:
        """Clear current session"""
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        try:
            if os.path.exists(self.session_file):
                os.remove(self.session_file)
        except Exception as e:
            logger.debug(f"Failed to remove session file: {e}")
    
    def set_tokens(self, access: str, refresh: str, expires_in: int = 900) -> None:
        """Set JWT tokens"""
        self.access_token = access
        self.refresh_token = refresh
        self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)  # 1min buffer
        self.save_session()
    
    def is_token_expired(self) -> bool:
        """Check if access token is expired"""
        if not self.access_token or not self.token_expires_at:
            return True
        return datetime.now() >= self.token_expires_at
    
    def has_valid_refresh_token(self) -> bool:
        """Check if we have a refresh token"""
        return bool(self.refresh_token)


class AuthlyClient:
    """
    Production-grade Python SDK for Authly API
    
    Provides comprehensive authentication, authorization, and user management
    capabilities for the Authly Enterprise Identity & Access Management platform.
    
    Features:
    - JWT authentication with automatic token refresh
    - Multi-Factor Authentication (MFA) support
    - Comprehensive user profile management
    - Role-based permission checking
    - API key management
    - Session persistence
    - Automatic retry with exponential backoff
    - Context manager support
    - Type hints and comprehensive documentation
    """
    
    def __init__(
        self,
        base_url: str,
        tenant: str,
        timeout: int = 30,
        max_retries: int = 3,
        session_file: Optional[str] = None,
        verify_ssl: bool = True,
        api_key: Optional[str] = None,
        debug: bool = False
    ):
        """
        Initialize Authly Client
        
        Args:
            base_url: Base URL of Authly API (e.g., "https://api.authly.com")
            tenant: Tenant slug for multi-tenant isolation
            timeout: Request timeout in seconds (default: 30)
            max_retries: Maximum number of retry attempts (default: 3)
            session_file: Path to session file for token persistence
            verify_ssl: Whether to verify SSL certificates (default: True)
            api_key: API key for service account authentication
            debug: Enable debug logging (default: False)
        
        Raises:
            ValueError: If base_url or tenant is invalid
            TenantError: If tenant format is invalid
        """
        # Validate inputs
        if not base_url or not base_url.startswith(('http://', 'https://')):
            raise ValueError("base_url must be a valid HTTP/HTTPS URL")
        
        if not tenant or not isinstance(tenant, str):
            raise TenantError("tenant must be a non-empty string")
        
        # Force HTTPS in production
        if base_url.startswith('http://') and 'localhost' not in base_url:
            logger.warning("Using HTTP in production is not recommended. Consider using HTTPS.")
        
        self.base_url = base_url.rstrip('/')
        self.tenant = tenant
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.api_key = api_key
        
        # Setup logging
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        
        # Initialize session management
        self.session_manager = SessionManager(session_file)
        
        # Setup HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'AuthlySDK/1.0.0 Python',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Tenant': self.tenant
        })
        
        if not self.verify_ssl:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning
            disable_warnings(InsecureRequestWarning)
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        if hasattr(self.session, 'close'):
            self.session.close()
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        files: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        auth_required: bool = True,
        auto_refresh: bool = True
    ) -> requests.Response:
        """
        Make HTTP request with automatic token refresh and error handling
        
        Args:
            method: HTTP method
            endpoint: API endpoint (relative to base_url)
            data: Request data for POST/PUT/PATCH
            params: URL parameters
            files: Files for multipart upload
            headers: Additional headers
            auth_required: Whether authentication is required
            auto_refresh: Whether to automatically refresh tokens
        
        Returns:
            requests.Response object
        
        Raises:
            AuthenticationError: Authentication failed
            AuthorizationError: Permission denied
            NetworkError: Network/connection error
            RateLimitError: Rate limit exceeded
            ValidationError: Request validation failed
        """
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        
        # Prepare headers
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        # Handle authentication
        if auth_required:
            if self.api_key:
                req_headers['Authorization'] = f'ApiKey {self.api_key}'
            else:
                # Check if token needs refresh
                if auto_refresh and self.session_manager.is_token_expired():
                    if self.session_manager.has_valid_refresh_token():
                        try:
                            self._refresh_tokens()
                        except Exception as e:
                            logger.debug(f"Token refresh failed: {e}")
                            raise AuthenticationError("Token refresh failed. Please login again.")
                    else:
                        raise AuthenticationError("No valid authentication token. Please login.")
                
                if self.session_manager.access_token:
                    req_headers['Authorization'] = f'Bearer {self.session_manager.access_token}'
                else:
                    raise AuthenticationError("No authentication token available")
        
        # Prepare request data
        if files:
            # For file uploads, don't set Content-Type (let requests handle it)
            req_headers.pop('Content-Type', None)
            json_data = None
        elif data:
            json_data = data
        else:
            json_data = None
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
                files=files,
                headers=req_headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Handle HTTP errors
            if response.status_code == 401:
                # Try token refresh once
                if auto_refresh and auth_required and not self.api_key:
                    if self.session_manager.has_valid_refresh_token():
                        try:
                            self._refresh_tokens()
                            # Retry with new token
                            req_headers['Authorization'] = f'Bearer {self.session_manager.access_token}'
                            response = self.session.request(
                                method=method,
                                url=url,
                                json=json_data,
                                params=params,
                                files=files,
                                headers=req_headers,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        except Exception:
                            pass
                
                if response.status_code == 401:
                    self.session_manager.clear_session()
                    raise AuthenticationError("Authentication failed", response.status_code)
            
            elif response.status_code == 403:
                try:
                    error_data = response.json()
                except:
                    error_data = {}
                raise AuthorizationError(
                    error_data.get('detail', 'Permission denied'),
                    response.status_code,
                    error_data
                )
            
            elif response.status_code == 429:
                raise RateLimitError("Rate limit exceeded", response.status_code)
            
            elif response.status_code >= 400:
                try:
                    error_data = response.json()
                except:
                    error_data = {'detail': response.text}
                
                if response.status_code < 500:
                    raise ValidationError(
                        error_data.get('detail', f'Request failed: {response.status_code}'),
                        response.status_code,
                        error_data
                    )
                else:
                    raise AuthlyError(
                        f"Server error: {response.status_code}",
                        response.status_code,
                        error_data
                    )
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {e}")
            raise NetworkError(f"Network error: {str(e)}")
    
    def _refresh_tokens(self) -> None:
        """Refresh JWT access token using refresh token"""
        if not self.session_manager.refresh_token:
            raise AuthenticationError("No refresh token available")
        
        try:
            response = self._make_request(
                'POST',
                '/api/auth/auth/refresh/',
                data={'refresh': self.session_manager.refresh_token},
                auth_required=False,
                auto_refresh=False
            )
            
            data = response.json()
            access_token = data.get('access')
            
            if access_token:
                # Keep existing refresh token, update access token
                self.session_manager.set_tokens(
                    access_token, 
                    self.session_manager.refresh_token,
                    expires_in=900  # 15 minutes
                )
                logger.debug("Token refreshed successfully")
            else:
                raise AuthenticationError("Invalid refresh token response")
                
        except Exception as e:
            self.session_manager.clear_session()
            raise AuthenticationError(f"Token refresh failed: {str(e)}")
    
    def set_tenant(self, tenant: str) -> None:
        """
        Set tenant for subsequent requests
        
        Args:
            tenant: Tenant slug
        """
        if not tenant:
            raise TenantError("Tenant cannot be empty")
        
        self.tenant = tenant
        self.session.headers['X-Tenant'] = tenant
    
    # ====== AUTHENTICATION METHODS ======
    
    def register(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
        bio: Optional[str] = None,
        privacy_profile_visible: bool = True,
        privacy_email_visible: bool = False,
        privacy_phone_visible: bool = False
    ) -> Dict[str, Any]:
        """
        Register a new user account
        
        Args:
            email: User email address
            password: Password (must meet security requirements)
            first_name: First name
            last_name: Last name
            phone: Phone number (optional)
            bio: User bio (optional)
            privacy_profile_visible: Profile visibility setting
            privacy_email_visible: Email visibility setting
            privacy_phone_visible: Phone visibility setting
        
        Returns:
            Dict with registration result and user_id
        
        Raises:
            ValidationError: If registration data is invalid
        """
        data = {
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'privacy_profile_visible': privacy_profile_visible,
            'privacy_email_visible': privacy_email_visible,
            'privacy_phone_visible': privacy_phone_visible
        }
        
        if phone:
            data['phone'] = phone
        if bio:
            data['bio'] = bio
        
        response = self._make_request(
            'POST',
            '/api/auth/auth/register/',
            data=data,
            auth_required=False
        )
        
        return response.json()
    
    def activate(self, uid: str, token: str) -> Dict[str, Any]:
        """
        Activate user account using email verification token
        
        Args:
            uid: User ID from activation email
            token: Activation token from email
        
        Returns:
            Activation result
        """
        response = self._make_request(
            'GET',
            f'/api/auth/auth/activate/{uid}/{token}/',
            auth_required=False
        )
        
        return response.json()
    
    def login(self, email: str, password: str, mfa_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Authenticate user and obtain JWT tokens
        
        Args:
            email: User email
            password: User password
            mfa_token: MFA token if required
        
        Returns:
            Dict with access token, refresh token, and user info
        
        Raises:
            AuthenticationError: If login fails
            MFARequiredError: If MFA token is required
        """
        data = {
            'email': email,
            'password': password
        }
        
        if mfa_token:
            data['mfa_token'] = mfa_token
        
        response = self._make_request(
            'POST',
            '/api/auth/auth/login/',
            data=data,
            auth_required=False
        )
        
        result = response.json()
        
        # Check if MFA is required
        if result.get('mfa_required'):
            raise MFARequiredError("MFA token required for authentication")
        
        # Store tokens
        access_token = result.get('access')
        refresh_token = result.get('refresh')
        
        if access_token and refresh_token:
            self.session_manager.set_tokens(access_token, refresh_token)
        
        return result
    
    def logout(self) -> Dict[str, Any]:
        """
        Logout user and revoke refresh token
        
        Returns:
            Logout confirmation
        """
        data = {}
        if self.session_manager.refresh_token:
            data['refresh'] = self.session_manager.refresh_token
        
        try:
            response = self._make_request(
                'POST',
                '/api/auth/auth/logout/',
                data=data
            )
            result = response.json()
        except Exception as e:
            logger.debug(f"Logout request failed: {e}")
            result = {'message': 'Logged out locally'}
        
        # Clear local session regardless of API response
        self.session_manager.clear_session()
        
        return result
    
    def refresh_token(self) -> Dict[str, Any]:
        """
        Manually refresh access token
        
        Returns:
            Dict with new access token
        """
        self._refresh_tokens()
        return {'access': self.session_manager.access_token}
    
    def forgot_password(self, email: str) -> Dict[str, Any]:
        """
        Request password reset email
        
        Args:
            email: User email address
        
        Returns:
            Password reset request confirmation
        """
        response = self._make_request(
            'POST',
            '/api/auth/auth/forgot_password/',
            data={'email': email},
            auth_required=False
        )
        
        return response.json()
    
    def reset_password(self, uid: str, token: str, new_password: str) -> Dict[str, Any]:
        """
        Reset password using token from email
        
        Args:
            uid: User ID from reset email
            token: Reset token from email
            new_password: New password
        
        Returns:
            Password reset confirmation
        """
        response = self._make_request(
            'POST',
            f'/api/auth/auth/reset-password/{uid}/{token}/',
            data={'new_password': new_password},
            auth_required=False
        )
        
        return response.json()
    
    # ====== MFA METHODS ======
    
    def mfa_enable(self) -> Dict[str, Any]:
        """
        Enable Multi-Factor Authentication and get QR code
        
        Returns:
            Dict with QR code data and backup codes
        """
        response = self._make_request(
            'POST',
            '/api/auth/mfa/enable/',
            data={}
        )
        
        return response.json()
    
    def mfa_verify(self, token: str) -> Dict[str, Any]:
        """
        Verify MFA token to complete setup or authenticate
        
        Args:
            token: 6-digit TOTP token
        
        Returns:
            Verification result
        """
        response = self._make_request(
            'POST',
            '/api/auth/mfa/verify/',
            data={'token': token}
        )
        
        return response.json()
    
    def mfa_disable(self, password: str) -> Dict[str, Any]:
        """
        Disable Multi-Factor Authentication
        
        Args:
            password: Current password for confirmation
        
        Returns:
            Disable confirmation
        """
        response = self._make_request(
            'POST',
            '/api/auth/mfa/disable/',
            data={'password': password}
        )
        
        return response.json()
    
    def mfa_status(self) -> Dict[str, Any]:
        """
        Get current MFA status
        
        Returns:
            Dict with MFA enabled status and device count
        """
        response = self._make_request(
            'GET',
            '/api/auth/mfa/status/'
        )
        
        return response.json()
    
    # ====== PROFILE MANAGEMENT ======
    
    def get_profile(self) -> Dict[str, Any]:
        """
        Get current user profile
        
        Returns:
            User profile data
        """
        response = self._make_request(
            'GET',
            '/api/users/me/'
        )
        
        return response.json()
    
    def update_profile(self, **data) -> Dict[str, Any]:
        """
        Update user profile
        
        Args:
            **data: Profile fields to update (first_name, last_name, phone, bio, privacy settings)
        
        Returns:
            Updated profile data
        """
        response = self._make_request(
            'PATCH',
            '/api/users/profile/',
            data=data
        )
        
        return response.json()
    
    def change_password(self, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Change user password
        
        Args:
            old_password: Current password
            new_password: New password
        
        Returns:
            Password change confirmation
        """
        response = self._make_request(
            'POST',
            '/api/users/change-password/',
            data={
                'old_password': old_password,
                'new_password': new_password
            }
        )
        
        return response.json()
    
    def upload_avatar(self, file_path: str) -> Dict[str, Any]:
        """
        Upload user avatar image
        
        Args:
            file_path: Path to image file
        
        Returns:
            Updated profile with new avatar URL
        
        Raises:
            FileNotFoundError: If file doesn't exist
            ValidationError: If file type is invalid
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Validate file type
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in allowed_extensions:
            raise ValidationError(f"Invalid file type. Allowed: {', '.join(allowed_extensions)}")
        
        with open(file_path, 'rb') as f:
            files = {'avatar': f}
            response = self._make_request(
                'POST',
                '/api/users/upload-avatar/',
                files=files
            )
        
        return response.json()
    
    # ====== AUTHORIZATION METHODS ======
    
    def get_my_permissions(self) -> List[str]:
        """
        Get current user's effective permissions
        
        Returns:
            List of permission codenames
        """
        response = self._make_request(
            'GET',
            '/api/roles/user-roles/me/permissions/'
        )
        
        data = response.json()
        return data.get('permissions', [])
    
    def has_permission(self, codename: str) -> bool:
        """
        Check if current user has specific permission
        
        Args:
            codename: Permission codename (e.g., 'users.manage_users')
        
        Returns:
            True if user has permission, False otherwise
        """
        try:
            permissions = self.get_my_permissions()
            return codename in permissions
        except Exception:
            return False
    
    # ====== API KEY MANAGEMENT ======
    
    def create_api_key(
        self,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create new API key
        
        Args:
            name: API key name/description
            scopes: List of scopes (optional)
            expires_at: Expiration date in ISO format (optional)
        
        Returns:
            Dict with API key details including the raw key (shown only once)
        """
        data = {'name': name}
        if scopes:
            data['scopes'] = scopes
        if expires_at:
            data['expires_at'] = expires_at
        
        response = self._make_request(
            'POST',
            '/api/api-keys/',
            data=data
        )
        
        return response.json()
    
    def list_api_keys(self) -> List[Dict[str, Any]]:
        """
        List user's API keys
        
        Returns:
            List of API key objects (without raw keys)
        """
        response = self._make_request(
            'GET',
            '/api/api-keys/'
        )
        
        data = response.json()
        return data.get('results', [])
    
    def revoke_api_key(self, key_id: str) -> Dict[str, Any]:
        """
        Revoke (delete) an API key
        
        Args:
            key_id: API key ID
        
        Returns:
            Revocation confirmation
        """
        response = self._make_request(
            'DELETE',
            f'/api/api-keys/{key_id}/'
        )
        
        return {'message': 'API key revoked successfully'}
    
    # ====== ENTERPRISE FEATURES ======
    
    # === Identity Federation ===
    
    def configure_sso(
        self, 
        provider_type: str,
        name: str,
        entity_id: str = None,
        sso_url: str = None,
        metadata_url: str = None,
        client_id: str = None,
        client_secret: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Configure SSO identity provider
        
        Args:
            provider_type: 'saml' or 'oidc'
            name: Display name for provider
            entity_id: SAML entity ID
            sso_url: SAML SSO URL
            metadata_url: SAML metadata URL  
            client_id: OIDC client ID
            client_secret: OIDC client secret
            **kwargs: Additional configuration
        
        Returns:
            Provider configuration
        """
        data = {
            'provider_type': provider_type,
            'name': name,
            'jit_enabled': kwargs.get('jit_enabled', True),
            'attribute_mapping': kwargs.get('attribute_mapping', {}),
            **kwargs
        }
        
        if provider_type == 'saml':
            data.update({
                'entity_id': entity_id,
                'sso_url': sso_url,
                'metadata_url': metadata_url,
            })
        elif provider_type == 'oidc':
            data.update({
                'client_id': client_id,
                'client_secret': client_secret,
                'authorization_endpoint': kwargs.get('authorization_endpoint'),
                'token_endpoint': kwargs.get('token_endpoint'),
                'userinfo_endpoint': kwargs.get('userinfo_endpoint'),
            })
        
        response = self._make_request('POST', '/api/federation/api/v1/identity-providers/', data=data)
        return response.json()
    
    def list_sso_providers(self) -> List[Dict[str, Any]]:
        """List configured SSO providers"""
        response = self._make_request('GET', '/api/federation/api/v1/identity-providers/')
        return response.json().get('results', [])
    
    def initiate_sso(self, provider_slug: str, tenant_slug: str = None) -> Dict[str, Any]:
        """
        Initiate SSO login
        
        Args:
            provider_slug: SSO provider identifier
            tenant_slug: Tenant identifier (defaults to current tenant)
        
        Returns:
            SSO redirect information
        """
        tenant_slug = tenant_slug or self.tenant
        response = self._make_request(
            'POST', 
            f'/api/federation/api/v1/sso/{tenant_slug}/{provider_slug}/init/',
            auth_required=False
        )
        return response.json()
    
    # === Scoped Token Management ===
    
    def create_scoped_token(
        self,
        scopes: List[str],
        audience: str,
        expires_in: int = 3600,
        permissions: List[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create scoped token for API access
        
        Args:
            scopes: List of scope names
            audience: Intended audience
            expires_in: Token lifetime in seconds
            permissions: Specific permissions
            **kwargs: Additional token options
        
        Returns:
            Token information including JWT
        """
        data = {
            'scopes': scopes,
            'audience': audience,
            'expires_in': expires_in,
            'permissions': permissions or [],
            **kwargs
        }
        
        response = self._make_request('POST', '/api/tokens/api/v1/tokens/', data=data)
        return response.json()
    
    def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect token to check validity and claims
        
        Args:
            token: JWT token to introspect
        
        Returns:
            Token introspection response
        """
        data = {'token': token}
        response = self._make_request('POST', '/api/tokens/api/v1/tokens/introspect/', data=data)
        return response.json()
    
    def list_scoped_tokens(self) -> List[Dict[str, Any]]:
        """List user's scoped tokens"""
        response = self._make_request('GET', '/api/tokens/api/v1/tokens/')
        return response.json().get('results', [])
    
    def revoke_scoped_token(self, token_id: str) -> Dict[str, Any]:
        """Revoke a scoped token"""
        response = self._make_request('DELETE', f'/api/tokens/api/v1/tokens/{token_id}/')
        return {'message': 'Token revoked successfully'}
    
    def get_available_scopes(self) -> List[Dict[str, Any]]:
        """Get scopes available to current user"""
        response = self._make_request('GET', '/api/tokens/api/v1/scopes/my-scopes/')
        return response.json()
    
    # === Billing Management ===
    
    def get_billing_plans(self) -> List[Dict[str, Any]]:
        """Get available billing plans"""
        response = self._make_request('GET', '/api/billing/api/v1/plans/pricing/', auth_required=False)
        return response.json().get('plans', [])
    
    def create_subscription(
        self,
        plan_id: str,
        billing_interval: str = 'monthly',
        payment_method_id: str = None
    ) -> Dict[str, Any]:
        """
        Create new subscription
        
        Args:
            plan_id: Billing plan ID
            billing_interval: 'monthly' or 'yearly'
            payment_method_id: Payment method ID
        
        Returns:
            Subscription information
        """
        data = {
            'plan_id': plan_id,
            'billing_interval': billing_interval,
            'payment_method_id': payment_method_id
        }
        
        response = self._make_request('POST', '/api/billing/api/v1/subscription/create_subscription/', data=data)
        return response.json()
    
    def get_subscription(self) -> Dict[str, Any]:
        """Get current subscription details"""
        response = self._make_request('GET', '/api/billing/api/v1/subscription/')
        results = response.json().get('results', [])
        return results[0] if results else {}
    
    def get_usage_metrics(self) -> Dict[str, Any]:
        """Get tenant usage metrics"""
        response = self._make_request('GET', '/api/billing/api/v1/subscription/usage_summary/')
        return response.json()
    
    def list_invoices(self) -> List[Dict[str, Any]]:
        """List tenant invoices"""
        response = self._make_request('GET', '/api/billing/api/v1/invoices/')
        return response.json().get('results', [])
    
    def download_invoice(self, invoice_id: str) -> Dict[str, Any]:
        """Get invoice download URL"""
        response = self._make_request('GET', f'/api/billing/api/v1/invoices/{invoice_id}/download/')
        return response.json()
    
    # === Tenant Customization ===
    
    def update_branding(
        self,
        company_name: str = None,
        logo_url: str = None,
        primary_color: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Update tenant branding
        
        Args:
            company_name: Company name
            logo_url: Logo URL
            primary_color: Primary brand color
            **kwargs: Additional branding options
        
        Returns:
            Updated branding configuration
        """
        data = {}
        if company_name:
            data['company_name'] = company_name
        if logo_url:
            data['logo_url'] = logo_url
        if primary_color:
            data['primary_color'] = primary_color
        data.update(kwargs)
        
        response = self._make_request('PATCH', '/api/customization/api/v1/branding/1/', data=data)
        return response.json()
    
    def get_branding(self) -> Dict[str, Any]:
        """Get current tenant branding"""
        response = self._make_request('GET', '/api/customization/api/v1/branding/')
        results = response.json().get('results', [])
        return results[0] if results else {}
    
    def preview_branding(self) -> Dict[str, Any]:
        """Get branding preview"""
        response = self._make_request('GET', '/api/customization/api/v1/branding/preview/')
        return response.json()
    
    # === Data Export & Compliance ===
    
    def export_data(
        self,
        export_type: str = 'backup',
        export_format: str = 'json',
        date_from: str = None,
        date_to: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Request data export
        
        Args:
            export_type: 'backup', 'users', 'audit_logs', 'compliance', 'gdpr'
            export_format: 'json', 'csv', 'xml', 'encrypted'
            date_from: Start date (ISO format)
            date_to: End date (ISO format)
            **kwargs: Additional export options
        
        Returns:
            Export request information
        """
        data = {
            'export_type': export_type,
            'export_format': export_format,
            'date_from': date_from,
            'date_to': date_to,
            **kwargs
        }
        
        response = self._make_request('POST', '/api/customization/api/v1/exports/', data=data)
        return response.json()
    
    def list_exports(self) -> List[Dict[str, Any]]:
        """List data exports"""
        response = self._make_request('GET', '/api/customization/api/v1/exports/')
        return response.json().get('results', [])
    
    def download_export(self, export_id: str) -> Dict[str, Any]:
        """Get export download information"""
        response = self._make_request('GET', f'/api/customization/api/v1/exports/{export_id}/download/')
        return response.json()
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report"""
        response = self._make_request('GET', '/api/customization/api/v1/compliance/compliance_report/')
        return response.json()
    
    # === Audit & Security Analytics ===
    
    def get_audit_logs(
        self,
        action: str = None,
        risk_level: str = None,
        date_from: str = None,
        date_to: str = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get audit logs with filtering
        
        Args:
            action: Filter by action type
            risk_level: Filter by risk level
            date_from: Start date
            date_to: End date
            limit: Number of results
        
        Returns:
            Audit log entries
        """
        params = {'limit': limit}
        if action:
            params['action'] = action
        if risk_level:
            params['risk_level'] = risk_level
        if date_from:
            params['timestamp__gte'] = date_from
        if date_to:
            params['timestamp__lte'] = date_to
        
        response = self._make_request('GET', '/api/audit/api/v1/audit-logs/', params=params)
        return response.json().get('results', [])
    
    def get_security_alerts(self, status: str = 'open') -> List[Dict[str, Any]]:
        """
        Get security alerts
        
        Args:
            status: Filter by status ('open', 'resolved', etc.)
        
        Returns:
            Security alerts
        """
        params = {'status': status} if status else {}
        response = self._make_request('GET', '/api/audit/api/v1/security-alerts/', params=params)
        return response.json().get('results', [])
    
    def get_audit_analytics(self) -> Dict[str, Any]:
        """Get audit analytics summary"""
        response = self._make_request('GET', '/api/audit/api/v1/audit-summary/')
        return response.json()
    
    # === Role Delegation ===
    
    def delegate_role(
        self,
        role_id: str,
        user_id: str,
        expires_in_days: int = 30,
        conditions: Dict = None
    ) -> Dict[str, Any]:
        """
        Delegate role to another user
        
        Args:
            role_id: Role to delegate
            user_id: Target user ID
            expires_in_days: Expiration in days
            conditions: ABAC conditions
        
        Returns:
            Delegation result
        """
        data = {
            'role_id': role_id,
            'user_id': user_id,
            'expires_in_days': expires_in_days,
            'conditions': conditions or {}
        }
        
        response = self._make_request('POST', '/api/roles/delegated-roles/delegate-role/', data=data)
        return response.json()
    
    def list_my_delegations(self) -> List[Dict[str, Any]]:
        """List roles delegated to current user"""
        response = self._make_request('GET', '/api/roles/delegated-roles/my-delegations/')
        return response.json()
    
    def revoke_delegation(self, user_role_id: str) -> Dict[str, Any]:
        """Revoke a delegated role assignment"""
        data = {'user_role_id': user_role_id}
        response = self._make_request('POST', '/api/roles/delegated-roles/revoke/', data=data)
        return response.json()
    
    # === Onboarding Management ===
    
    def get_onboarding_progress(self) -> Dict[str, Any]:
        """Get tenant onboarding progress"""
        response = self._make_request('GET', '/api/customization/api/v1/onboarding/progress/')
        return response.json()
    
    def complete_onboarding_step(self, step_id: str, result: Dict = None) -> Dict[str, Any]:
        """Complete an onboarding step"""
        data = {'result': result or {}}
        response = self._make_request('POST', f'/api/customization/api/v1/onboarding/{step_id}/complete-step/', data=data)
        return response.json()
    
    def auto_complete_onboarding(self) -> Dict[str, Any]:
        """Auto-complete eligible onboarding steps"""
        response = self._make_request('POST', '/api/customization/api/v1/onboarding/auto_complete/')
        return response.json()
    
    # ====== UTILITY METHODS ======
    
    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated"""
        return bool(
            self.api_key or 
            (self.session_manager.access_token and not self.session_manager.is_token_expired())
        )
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """
        Get basic user info from current session
        
        Returns:
            User info if authenticated, None otherwise
        """
        try:
            return self.get_profile()
        except Exception:
            return None
    
    def healthcheck(self) -> Dict[str, Any]:
        """
        Perform API health check
        
        Returns:
            Health status
        """
        try:
            response = self._make_request(
                'GET',
                '/api/health/',
                auth_required=False
            )
            return response.json()
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


# ====== EXAMPLE USAGE ======
if __name__ == "__main__":
    """
    Example usage demonstrating complete workflow:
    Register → Activate → Login → MFA → Profile → API Key
    """
    import sys
    import getpass
    
    # Example configuration
    API_URL = "http://localhost:8000"  # Change to your API URL
    TENANT = "test"  # Change to your tenant
    
    def demo_workflow():
        """Demonstrate complete SDK workflow"""
        
        print("🚀 Authly SDK Demo")
        print("=" * 50)
        
        # Initialize client with context manager
        with AuthlyClient(
            base_url=API_URL,
            tenant=TENANT,
            debug=True
        ) as client:
            
            print(f"📡 Connected to {API_URL} (tenant: {TENANT})")
            
            # Example 1: Registration
            print("\n1️⃣ User Registration")
            email = input("Enter email: ")
            password = getpass.getpass("Enter password: ")
            first_name = input("Enter first name: ")
            last_name = input("Enter last name: ")
            
            try:
                result = client.register(
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                print(f"✅ Registration successful: {result['message']}")
                user_id = result['user_id']
            except ValidationError as e:
                print(f"❌ Registration failed: {e}")
                return
            
            # Example 2: Login (skip activation for demo)
            print("\n2️⃣ User Login")
            try:
                tokens = client.login(email, password)
                print(f"✅ Login successful!")
                print(f"🔑 Access token: {tokens['access'][:20]}...")
                
                user_info = tokens.get('user', {})
                print(f"👤 Welcome {user_info.get('first_name')} {user_info.get('last_name')}")
                
                if user_info.get('mfa_enabled'):
                    print("🔐 MFA is enabled")
                else:
                    print("🔓 MFA is not enabled")
                    
            except MFARequiredError:
                print("🔐 MFA token required")
                mfa_token = input("Enter MFA token: ")
                tokens = client.login(email, password, mfa_token)
                print("✅ Login with MFA successful!")
            except AuthenticationError as e:
                print(f"❌ Login failed: {e}")
                return
            
            # Example 3: Profile Management
            print("\n3️⃣ Profile Management")
            try:
                profile = client.get_profile()
                print(f"👤 Current profile:")
                print(f"   - Name: {profile['first_name']} {profile['last_name']}")
                print(f"   - Email: {profile['email']}")
                print(f"   - Phone: {profile.get('phone', 'Not set')}")
                
                # Update profile
                updated = client.update_profile(
                    bio=f"Updated via SDK at {datetime.now().isoformat()}"
                )
                print(f"✅ Profile updated")
                
            except Exception as e:
                print(f"❌ Profile error: {e}")
            
            # Example 4: Permissions
            print("\n4️⃣ Permission Check")
            try:
                permissions = client.get_my_permissions()
                print(f"🔐 Your permissions ({len(permissions)}):")
                for perm in permissions[:5]:  # Show first 5
                    print(f"   - {perm}")
                if len(permissions) > 5:
                    print(f"   ... and {len(permissions) - 5} more")
                
                # Check specific permission
                can_manage_users = client.has_permission('users.manage_users')
                print(f"🔍 Can manage users: {'✅ Yes' if can_manage_users else '❌ No'}")
                
            except Exception as e:
                print(f"❌ Permission error: {e}")
            
            # Example 5: API Key Management
            print("\n5️⃣ API Key Management")
            try:
                # Create API key
                api_key = client.create_api_key(
                    name="SDK Demo Key",
                    expires_at=(datetime.now() + timedelta(days=30)).isoformat()
                )
                print(f"🔑 Created API key: {api_key['name']}")
                print(f"   Key: {api_key['key'][:20]}...")
                print(f"   Expires: {api_key['expires_at']}")
                
                # List API keys
                keys = client.list_api_keys()
                print(f"📋 Total API keys: {len(keys)}")
                
            except Exception as e:
                print(f"❌ API key error: {e}")
            
            # Example 6: MFA Setup (optional)
            print("\n6️⃣ MFA Setup (Optional)")
            setup_mfa = input("Enable MFA? (y/N): ").lower() == 'y'
            if setup_mfa:
                try:
                    mfa_data = client.mfa_enable()
                    print(f"🔐 MFA enabled!")
                    print(f"📱 Scan QR code: {mfa_data.get('qr_code_url', 'N/A')}")
                    print(f"🔑 Manual key: {mfa_data.get('manual_key', 'N/A')}")
                    
                    token = input("Enter TOTP token from your app: ")
                    verify_result = client.mfa_verify(token)
                    print(f"✅ MFA verified: {verify_result}")
                    
                except Exception as e:
                    print(f"❌ MFA setup error: {e}")
            
            print(f"\n🎉 Demo completed successfully!")
            print(f"🔐 Session saved for future use")
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo_workflow()
    else:
        print(__doc__)
        print("\nRun with 'demo' argument to see interactive demo:")
        print("python authly_client_sdk.py demo")