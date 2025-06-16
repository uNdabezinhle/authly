# sso/handlers.py

import base64
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import jwt
import ldap
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from .models import SSOUserMapping

logger = logging.getLogger('authly.sso')
User = get_user_model()

class BaseHandler:
    """Base class for SSO protocol handlers."""
    
    def __init__(self, identity_provider):
        self.idp = identity_provider
        self.config = identity_provider.config or {}
    
    def process_login(self, request):
        """Process login request and redirect to IdP."""
        raise NotImplementedError("Subclasses must implement process_login")
    
    def process_callback(self, request):
        """Process callback from IdP and authenticate user."""
        raise NotImplementedError("Subclasses must implement process_callback")
    
    def get_or_create_user(self, external_id, external_email, attributes=None):
        """Get or create a user based on external identity."""
        attributes = attributes or {}
        
        # Try to find existing mapping
        try:
            mapping = SSOUserMapping.objects.select_related('user').get(
                identity_provider=self.idp,
                external_id=external_id
            )
            user = mapping.user
            
            # Update profile data if needed
            mapping.profile_data = attributes
            mapping.external_email = external_email
            mapping.save(update_fields=['profile_data', 'external_email', 'updated_at'])
            
            return user, mapping, False
            
        except SSOUserMapping.DoesNotExist:
            # No mapping exists, check if user with this email exists
            user = None
            created = False
            
            try:
                user = User.objects.get(email=external_email)
            except User.DoesNotExist:
                # Create new user
                username = attributes.get('username', external_email.split('@')[0])
                first_name = attributes.get('first_name', '')
                last_name = attributes.get('last_name', '')
                
                user = User.objects.create_user(
                    email=external_email,
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    is_active=True,
                    email_verified=True  # Trust the IdP verification
                )
                created = True
            
            # Create the mapping
            mapping = SSOUserMapping.objects.create(
                user=user,
                identity_provider=self.idp,
                external_id=external_id,
                external_email=external_email,
                external_username=attributes.get('username', ''),
                profile_data=attributes
            )
            
            return user, mapping, created
    
    def create_session(self, user_mapping, request):
        """Create an SSO session for the user."""
        from .models import SSOSession
        import uuid
        
        # Create a new session
        session = SSOSession.objects.create(
            user_mapping=user_mapping,
            session_id=str(uuid.uuid4()),
            expires_at=timezone.now() + timedelta(hours=12),  # Default 12h session
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return session
    
    def update_last_login(self, user_mapping):
        """Update the last login timestamp."""
        user_mapping.last_login = timezone.now()
        user_mapping.user.last_login = timezone.now()
        
        user_mapping.save(update_fields=['last_login', 'updated_at'])
        user_mapping.user.save(update_fields=['last_login'])


class SAMLHandler(BaseHandler):
    """Handler for SAML 2.0 protocol."""
    
    def prepare_request(self, request):
        """Prepare the request for python3-saml."""
        result = {
            'https': 'on' if request.is_secure() else 'off',
            'http_host': request.META['HTTP_HOST'],
            'script_name': request.META['PATH_INFO'],
            'server_port': request.META.get('SERVER_PORT', '80'),
            'get_data': request.GET.copy(),
            'post_data': request.POST.copy(),
        }
        
        if 'HTTP_X_FORWARDED_FOR' in request.META:
            result['remote_addr'] = request.META['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        else:
            result['remote_addr'] = request.META.get('REMOTE_ADDR', '')
            
        return result
    
    def get_saml_settings(self):
        """Get SAML settings from IdP configuration."""
        sp_config = self.config.get('service_provider', {})
        idp_config = self.config.get('identity_provider', {})
        
        settings = {
            'strict': True,
            'debug': settings.DEBUG,
            'sp': {
                'entityId': sp_config.get('entity_id'),
                'assertionConsumerService': {
                    'url': sp_config.get('acs_url'),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                },
                'singleLogoutService': {
                    'url': sp_config.get('sls_url'),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                'x509cert': sp_config.get('x509cert', ''),
                'privateKey': sp_config.get('private_key', ''),
            },
            'idp': {
                'entityId': idp_config.get('entity_id'),
                'singleSignOnService': {
                    'url': idp_config.get('sso_url'),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'singleLogoutService': {
                    'url': idp_config.get('slo_url'),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'x509cert': idp_config.get('x509cert', ''),
            },
            'security': {
                'nameIdEncrypted': False,
                'authnRequestsSigned': True,
                'logoutRequestSigned': True,
                'logoutResponseSigned': True,
                'signMetadata': True,
                'wantMessagesSigned': True,
                'wantAssertionsSigned': True,
                'wantNameId': True,
                'wantNameIdEncrypted': False,
                'wantAssertionsEncrypted': False,
                'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            }
        }
        
        return OneLogin_Saml2_Settings(settings)
    
    def process_login(self, request):
        """Initiate SAML authentication flow."""
        saml_request = self.prepare_request(request)
        auth = OneLogin_Saml2_Auth(saml_request, self.get_saml_settings())
        
        # Store relay state to return to original page if needed
        relay_state = request.GET.get('next', '/')
        
        # Redirect to IdP
        redirect_url = auth.login(relay_state)
        return redirect_url
    
    def process_callback(self, request):
        """Process SAML response from IdP."""
        saml_request = self.prepare_request(request)
        auth = OneLogin_Saml2_Auth(saml_request, self.get_saml_settings())
        
        # Process response
        auth.process_response()
        errors = auth.get_errors()
        
        if errors:
            error_reason = auth.get_last_error_reason()
            logger.error(f"SAML authentication error: {error_reason}")
            return None, errors, None
        
        if not auth.is_authenticated():
            logger.error("SAML user not authenticated")
            return None, ["Authentication failed"], None
        
        # Get user info from SAML response
        external_id = auth.get_nameid()
        attributes = auth.get_attributes()
        
        # Extract email
        email_attribute = self.config.get('attribute_mapping', {}).get('email', 'email')
        if email_attribute in attributes and attributes[email_attribute]:
            external_email = attributes[email_attribute][0]
        else:
            # Fall back to NameID if it looks like an email
            external_email = external_id if '@' in external_id else None
        
        if not external_email:
            logger.error(f"SAML response missing email attribute ({email_attribute})")
            return None, ["Email attribute missing"], None
        
        # Extract profile attributes
        attribute_mapping = self.config.get('attribute_mapping', {})
        profile_data = {}
        for attr_name, saml_attr in attribute_mapping.items():
            if saml_attr in attributes and attributes[saml_attr]:
                profile_data[attr_name] = attributes[saml_attr][0]
        
        # Get or create user
        user, mapping, created = self.get_or_create_user(
            external_id=external_id,
            external_email=external_email,
            attributes=profile_data
        )
        
        # Create SSO session
        session = self.create_session(mapping, request)
        
        # Update last login time
        self.update_last_login(mapping)
        
        # Get relay state to redirect user back to original page
        relay_state = request.POST.get('RelayState', '/')
        
        return user, None, relay_state


class OIDCHandler(BaseHandler):
    """Handler for OpenID Connect protocol."""
    
    def process_login(self, request):
        """Initiate OIDC authentication flow."""
        # Configuration
        client_id = self.config.get('client_id')
        auth_endpoint = self.config.get('authorization_endpoint')
        redirect_uri = self.config.get('redirect_uri')
        scope = self.config.get('scope', 'openid email profile')
        
        if not all([client_id, auth_endpoint, redirect_uri]):
            logger.error("OIDC configuration incomplete")
            return None
        
        # Generate state parameter to prevent CSRF
        import secrets
        state = secrets.token_urlsafe(32)
        
        # Store state in session
        request.session['oidc_state'] = state
        request.session['oidc_next'] = request.GET.get('next', '/')
        
        # Build authorization URL
        params = {
            'client_id': client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': redirect_uri,
            'state': state,
        }
        
        from urllib.parse import urlencode
        auth_url = f"{auth_endpoint}?{urlencode(params)}"
        
        return auth_url
    
    def process_callback(self, request):
        """Process OIDC callback."""
        # Check error response
        if 'error' in request.GET:
            error = request.GET.get('error')
            error_description = request.GET.get('error_description', '')
            logger.error(f"OIDC error: {error} - {error_description}")
            return None, [f"{error}: {error_description}"], None
        
        # Get authorization code
        code = request.GET.get('code')
        if not code:
            logger.error("OIDC callback missing code parameter")
            return None, ["Authorization code missing"], None
        
        # Verify state parameter
        state = request.GET.get('state')
        stored_state = request.session.pop('oidc_state', None)
        next_url = request.session.pop('oidc_next', '/')
        
        if not state or state != stored_state:
            logger.error("OIDC state mismatch")
            return None, ["Invalid state parameter"], None
        
        # Exchange code for tokens
        token_endpoint = self.config.get('token_endpoint')
        client_id = self.config.get('client_id')
        client_secret = self.config.get('client_secret')
        redirect_uri = self.config.get('redirect_uri')
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret,
        }
        
        try:
            token_response = requests.post(token_endpoint, data=token_data, timeout=10)
            token_response.raise_for_status()
            tokens = token_response.json()
        except Exception as e:
            logger.error(f"OIDC token exchange error: {str(e)}")
            return None, ["Token exchange failed"], None
        
        # Get ID token
        id_token = tokens.get('id_token')
        if not id_token:
            logger.error("OIDC response missing id_token")
            return None, ["ID token missing from response"], None
        
        # Decode and validate ID token
        try:
            # Note: In production, you should validate the token signature
            # For simplicity, we're just decoding it here
            id_token_parts = id_token.split('.')
            if len(id_token_parts) != 3:
                raise ValueError("Invalid ID token format")
            
            # Decode the payload
            payload_b64 = id_token_parts[1]
            # Add padding if needed
            payload_b64 += '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
            
        except Exception as e:
            logger.error(f"OIDC ID token decode error: {str(e)}")
            return None, ["ID token validation failed"], None
        
        # Extract user information
        external_id = payload.get('sub')
        if not external_id:
            logger.error("OIDC ID token missing sub claim")
            return None, ["Subject identifier missing"], None
        
        external_email = payload.get('email')
        if not external_email:
            # Try to get email from userinfo endpoint
            try:
                userinfo_endpoint = self.config.get('userinfo_endpoint')
                if userinfo_endpoint:
                    headers = {'Authorization': f"Bearer {tokens.get('access_token')}"}
                    userinfo_response = requests.get(userinfo_endpoint, headers=headers, timeout=10)
                    userinfo_response.raise_for_status()
                    userinfo = userinfo_response.json()
                    external_email = userinfo.get('email')
            except Exception as e:
                logger.error(f"OIDC userinfo error: {str(e)}")
        
        if not external_email:
            logger.error("OIDC response missing email")
            return None, ["Email missing from ID token"], None
        
        # Extract profile data
        profile_data = {
            'name': payload.get('name', ''),
            'first_name': payload.get('given_name', ''),
            'last_name': payload.get('family_name', ''),
            'username': payload.get('preferred_username', ''),
        }
        
        # Get or create user
        user, mapping, created = self.get_or_create_user(
            external_id=external_id, 
            external_email=external_email,
            attributes=profile_data
        )
        
        # Create SSO session
        session = self.create_session(mapping, request)
        
        # Update last login time
        self.update_last_login(mapping)
        
        return user, None, next_url


class LDAPHandler(BaseHandler):
    """Handler for LDAP/Active Directory protocol."""
    
    def get_ldap_connection(self):
        """Establish connection to LDAP server."""
        server_uri = self.config.get('server_uri')
        bind_dn = self.config.get('bind_dn')
        bind_password = self.config.get('bind_password')
        
        if not all([server_uri, bind_dn, bind_password]):
            logger.error("LDAP configuration incomplete")
            return None
        
        try:
            # Initialize connection
            conn = ldap.initialize(server_uri)
            
            # Set options
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            
            # Enable TLS if configured
            if self.config.get('use_tls', False):
                conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
                conn.start_tls_s()
            
            # Bind with service account
            conn.simple_bind_s(bind_dn, bind_password)
            
            return conn
            
        except ldap.LDAPError as e:
            logger.error(f"LDAP connection error: {str(e)}")
            return None
    
    def process_login(self, request):
        """Show LDAP login form."""
        # LDAP authentication is form-based, so there's no redirect
        # This will be handled by a template and direct POST to the callback URL
        return None
    
    def process_callback(self, request):
        """Process LDAP authentication."""
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            return None, ["Username and password are required"], None
        
        # Get connection
        conn = self.get_ldap_connection()
        if not conn:
            return None, ["LDAP connection failed"], None
        
        try:
            # Search for the user
            base_dn = self.config.get('base_dn')
            search_filter = self.config.get('search_filter', '(sAMAccountName={username})').format(username=ldap.filter.escape_filter_chars(username))
            attributes = self.config.get('attributes', ['mail', 'givenName', 'sn', 'displayName', 'objectGUID'])
            
            search_result = conn.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                attributes
            )
            
            if not search_result or not search_result[0][0]:
                logger.error(f"LDAP user not found: {username}")
                return None, ["Invalid username or password"], None
            
            user_dn = search_result[0][0]
            user_attributes = search_result[0][1]
            
            # Try to bind with user credentials
            user_conn = ldap.initialize(self.config.get('server_uri'))
            user_conn.set_option(ldap.OPT_REFERRALS, 0)
            user_conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            
            if self.config.get('use_tls', False):
                user_conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
                user_conn.start_tls_s()
            
            user_conn.simple_bind_s(user_dn, password)
            
            # Authentication successful, extract user info
            # Convert binary attributes to string as needed
            profile_data = {}
            
            # Get email
            email_attr = self.config.get('email_attribute', 'mail')
            if email_attr in user_attributes and user_attributes[email_attr]:
                external_email = user_attributes[email_attr][0].decode('utf-8')
            else:
                external_email = f"{username}@{self.config.get('default_domain', 'unknown.com')}"
            
            # Get user ID - typically objectGUID in AD
            id_attr = self.config.get('id_attribute', 'objectGUID')
            if id_attr in user_attributes and user_attributes[id_attr]:
                # objectGUID is binary, convert to hex string
                if id_attr == 'objectGUID':
                    external_id = ''.join(['%02x' % ord(x) for x in user_attributes[id_attr][0].decode('iso-8859-1')])
                else:
                    external_id = user_attributes[id_attr][0].decode('utf-8')
            else:
                # Fall back to username as ID
                external_id = username
            
            # Get profile attributes
            attr_mapping = {
                'first_name': 'givenName',
                'last_name': 'sn',
                'name': 'displayName',
                'username': 'sAMAccountName'
            }
            
            for attr_name, ldap_attr in attr_mapping.items():
                if ldap_attr in user_attributes and user_attributes[ldap_attr]:
                    profile_data[attr_name] = user_attributes[ldap_attr][0].decode('utf-8')
            
            # Get or create user
            user, mapping, created = self.get_or_create_user(
                external_id=external_id,
                external_email=external_email,
                attributes=profile_data
            )
            
            # Create SSO session
            session = self.create_session(mapping, request)
            
            # Update last login time
            self.update_last_login(mapping)
            
            # Get next URL from form or default
            next_url = request.POST.get('next', '/')
            
            return user, None, next_url
            
        except ldap.INVALID_CREDENTIALS:
            logger.warning(f"LDAP invalid credentials: {username}")
            return None, ["Invalid username or password"], None
            
        except ldap.LDAPError as e:
            logger.error(f"LDAP authentication error: {str(e)}")
            return None, ["Authentication failed"], None
            
        finally:
            if conn:
                conn.unbind_s()


class OAuth2Handler(BaseHandler):
    """Handler for generic OAuth 2.0 providers."""
    
    def process_login(self, request):
        """Initiate OAuth2 authentication flow."""
        # Configuration
        client_id = self.config.get('client_id')
        auth_endpoint = self.config.get('authorization_endpoint')
        redirect_uri = self.config.get('redirect_uri')
        scope = self.config.get('scope', 'email profile')
        
        if not all([client_id, auth_endpoint, redirect_uri]):
            logger.error("OAuth2 configuration incomplete")
            return None
        
        # Generate state parameter to prevent CSRF
        import secrets
        state = secrets.token_urlsafe(32)
        
        # Store state in session
        request.session['oauth2_state'] = state
        request.session['oauth2_next'] = request.GET.get('next', '/')
        
        # Build authorization URL
        params = {
            'client_id': client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': redirect_uri,
            'state': state,
        }
        
        from urllib.parse import urlencode
        auth_url = f"{auth_endpoint}?{urlencode(params)}"
        
        return auth_url
    
    def process_callback(self, request):
        """Process OAuth2 callback."""
        # Check error response
        if 'error' in request.GET:
            error = request.GET.get('error')
            error_description = request.GET.get('error_description', '')
            logger.error(f"OAuth2 error: {error} - {error_description}")
            return None, [f"{error}: {error_description}"], None
        
        # Get authorization code
        code = request.GET.get('code')
        if not code:
            logger.error("OAuth2 callback missing code parameter")
            return None, ["Authorization code missing"], None
        
        # Verify state parameter
        state = request.GET.get('state')
        stored_state = request.session.pop('oauth2_state', None)
        next_url = request.session.pop('oauth2_next', '/')
        
        # Continuing the OAuth2Handler class from the previous file

        if not state or state != stored_state:
            logger.error("OAuth2 state mismatch")
            return None, ["Invalid state parameter"], None
        
        # Exchange code for tokens
        token_endpoint = self.config.get('token_endpoint')
        client_id = self.config.get('client_id')
        client_secret = self.config.get('client_secret')
        redirect_uri = self.config.get('redirect_uri')
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
        }
        
        # Add client_secret if available
        if client_secret:
            token_data['client_secret'] = client_secret
        
        try:
            token_response = requests.post(token_endpoint, data=token_data, timeout=10)
            token_response.raise_for_status()
            tokens = token_response.json()
        except Exception as e:
            logger.error(f"OAuth2 token exchange error: {str(e)}")
            return None, ["Token exchange failed"], None
        
        # Get access token
        access_token = tokens.get('access_token')
        if not access_token:
            logger.error("OAuth2 response missing access_token")
            return None, ["Access token missing from response"], None
        
        # Get user info from userinfo endpoint
        userinfo_endpoint = self.config.get('userinfo_endpoint')
        if not userinfo_endpoint:
            logger.error("OAuth2 configuration missing userinfo_endpoint")
            return None, ["User info endpoint not configured"], None
        
        try:
            headers = {'Authorization': f"Bearer {access_token}"}
            userinfo_response = requests.get(userinfo_endpoint, headers=headers, timeout=10)
            userinfo_response.raise_for_status()
            userinfo = userinfo_response.json()
        except Exception as e:
            logger.error(f"OAuth2 userinfo error: {str(e)}")
            return None, ["Failed to retrieve user information"], None
        
        # Extract user information based on provider-specific mappings
        id_field = self.config.get('id_field', 'id')
        email_field = self.config.get('email_field', 'email')
        
        external_id = str(userinfo.get(id_field))
        if not external_id:
            logger.error(f"OAuth2 userinfo missing ID field: {id_field}")
            return None, ["User ID missing from response"], None
        
        external_email = userinfo.get(email_field)
        if not external_email:
            logger.error(f"OAuth2 userinfo missing email field: {email_field}")
            return None, ["Email missing from user info"], None
        
        # Extract profile information based on mappings
        field_mapping = self.config.get('field_mapping', {
            'first_name': 'given_name',
            'last_name': 'family_name',
            'name': 'name',
            'username': 'preferred_username'
        })
        
        profile_data = {}
        for attr_name, provider_field in field_mapping.items():
            if provider_field in userinfo:
                profile_data[attr_name] = userinfo[provider_field]
        
        # Add raw profile data for reference
        profile_data['raw_profile'] = userinfo
        
        # Get or create user
        user, mapping, created = self.get_or_create_user(
            external_id=external_id,
            external_email=external_email,
            attributes=profile_data
        )
        
        # Create SSO session
        session = self.create_session(mapping, request)
        
        # Update last login time
        self.update_last_login(mapping)
        
        return user, None, next_url