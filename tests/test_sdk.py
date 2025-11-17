#!/usr/bin/env python3
"""
Comprehensive tests for Authly Python SDK using requests_mock

This test suite covers:
1. Authentication flow (register, login, MFA)
2. Profile management (get, update, avatar upload)
3. API key management (create, list, revoke)
4. Permission checking
5. Session management
6. Error handling
7. Rate limiting scenarios
"""

import json
import unittest
from unittest.mock import patch, mock_open
import requests_mock
import tempfile
import os
import sys

# Add the project root to Python path to import SDK
sys.path.insert(0, '/home/Dev/csert-dev/authly-api')

from authly_client_sdk import (
    AuthlyClient, AuthlyError, AuthenticationError, 
    AuthorizationError, MFARequiredError, ValidationError
)

class TestAuthlySDK(unittest.TestCase):
    """Comprehensive test suite for Authly SDK"""
    
    def setUp(self):
        """Set up test environment"""
        self.base_url = "https://test.authly.com"
        self.tenant = "test-tenant"
        
        # Create temporary session file
        self.temp_session_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_session_file.close()
        
        # Initialize client
        self.client = AuthlyClient(
            base_url=self.base_url,
            tenant=self.tenant,
            session_file=self.temp_session_file.name,
            debug=True
        )
        
        # Test user data
        self.test_user = {
            'email': 'test@example.com',
            'password': 'TestPassword123!',
            'first_name': 'John',
            'last_name': 'Doe'
        }
        
        # Mock JWT tokens
        self.mock_tokens = {
            'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjMwNTI0MDAwLCJqdGkiOiJhYmMxMjMiLCJ1c2VyX2lkIjoxfQ.test_access_token',
            'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTYzMTE4ODgwMCwianRpIjoiZGVmNDU2IiwidXNlcl9pZCI6MX0.test_refresh_token'
        }
        
        # Mock user profile
        self.mock_profile = {
            'id': 'user-uuid-123',
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'phone': '+1-555-0123',
            'avatar': '/media/avatars/test.jpg',
            'bio': 'Test user biography'
        }
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary session file
        if os.path.exists(self.temp_session_file.name):
            os.unlink(self.temp_session_file.name)
    
    @requests_mock.Mocker()
    def test_user_registration(self, m):
        """Test user registration flow"""
        # Mock registration response
        m.post(
            f"{self.base_url}/api/auth/register/",
            json={
                'message': 'Registration successful. Please check your email to activate your account.',
                'user_id': 'user-uuid-123'
            },
            status_code=201
        )
        
        result = self.client.register(
            email=self.test_user['email'],
            password=self.test_user['password'],
            first_name=self.test_user['first_name'],
            last_name=self.test_user['last_name']
        )
        
        self.assertIn('message', result)
        self.assertIn('user_id', result)
        
        # Verify request was made correctly
        self.assertEqual(len(m.request_history), 1)
        req = m.request_history[0]
        self.assertEqual(req.method, 'POST')
        self.assertIn('X-Tenant', req.headers)
        self.assertEqual(req.headers['X-Tenant'], self.tenant)
        
        # Verify request body
        body = json.loads(req.body)
        self.assertEqual(body['email'], self.test_user['email'])
        self.assertEqual(body['first_name'], self.test_user['first_name'])
    
    @requests_mock.Mocker()
    def test_successful_login(self, m):
        """Test successful login flow"""
        # Mock login response
        login_response = {
            'access': self.mock_tokens['access'],
            'refresh': self.mock_tokens['refresh'],
            'user': {
                'id': 'user-uuid-123',
                'email': self.test_user['email'],
                'first_name': self.test_user['first_name'],
                'last_name': self.test_user['last_name'],
                'mfa_enabled': False
            }
        }
        
        m.post(
            f"{self.base_url}/api/auth/login/",
            json=login_response,
            status_code=200
        )
        
        tokens = self.client.login(
            email=self.test_user['email'],
            password=self.test_user['password']
        )
        
        self.assertEqual(tokens['access'], self.mock_tokens['access'])
        self.assertEqual(tokens['refresh'], self.mock_tokens['refresh'])
        self.assertTrue(self.client.is_authenticated())
        
        # Verify tokens are stored
        self.assertIsNotNone(self.client.session_manager.get_access_token())
        self.assertIsNotNone(self.client.session_manager.get_refresh_token())
    
    @requests_mock.Mocker()
    def test_login_with_mfa(self, m):
        """Test login with MFA requirement"""
        # First login attempt - MFA required
        m.post(
            f"{self.base_url}/api/auth/login/",
            json={'error': 'MFA token required'},
            status_code=400
        )
        
        with self.assertRaises(MFARequiredError):
            self.client.login(
                email=self.test_user['email'],
                password=self.test_user['password']
            )
        
        # Second attempt with MFA token
        m.post(
            f"{self.base_url}/api/auth/login/",
            json={
                'access': self.mock_tokens['access'],
                'refresh': self.mock_tokens['refresh'],
                'user': {
                    'id': 'user-uuid-123',
                    'email': self.test_user['email'],
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'mfa_enabled': True
                }
            },
            status_code=200
        )
        
        tokens = self.client.login(
            email=self.test_user['email'],
            password=self.test_user['password'],
            mfa_token='123456'
        )
        
        self.assertIn('access', tokens)
        self.assertTrue(tokens['user']['mfa_enabled'])
    
    @requests_mock.Mocker()
    def test_get_profile(self, m):
        """Test getting user profile"""
        # Set up authenticated client
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        # Mock profile response
        m.get(
            f"{self.base_url}/api/users/profile/",
            json=self.mock_profile,
            status_code=200
        )
        
        profile = self.client.get_profile()
        
        self.assertEqual(profile['email'], self.test_user['email'])
        self.assertEqual(profile['first_name'], 'John')
        self.assertEqual(profile['last_name'], 'Doe')
        
        # Verify Authorization header
        req = m.request_history[0]
        self.assertIn('Authorization', req.headers)
        self.assertTrue(req.headers['Authorization'].startswith('Bearer'))
    
    @requests_mock.Mocker()
    def test_update_profile(self, m):
        """Test updating user profile"""
        # Set up authenticated client
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        # Mock update response
        updated_profile = self.mock_profile.copy()
        updated_profile['first_name'] = 'Jane'
        updated_profile['bio'] = 'Updated bio'
        
        m.patch(
            f"{self.base_url}/api/users/profile/",
            json=updated_profile,
            status_code=200
        )
        
        result = self.client.update_profile(
            first_name='Jane',
            bio='Updated bio'
        )
        
        self.assertEqual(result['first_name'], 'Jane')
        self.assertEqual(result['bio'], 'Updated bio')
        
        # Verify request body
        req = m.request_history[0]
        body = json.loads(req.body)
        self.assertEqual(body['first_name'], 'Jane')
        self.assertEqual(body['bio'], 'Updated bio')
    
    @requests_mock.Mocker()
    def test_api_key_management(self, m):
        """Test API key creation, listing, and revocation"""
        # Set up authenticated client
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        # Test API key creation
        mock_api_key = {
            'id': 'key-uuid-123',
            'name': 'Test API Key',
            'key': 'sk_test_123456789',
            'created_at': '2023-01-01T00:00:00Z',
            'expires_at': '2024-01-01T00:00:00Z',
            'scopes': ['read', 'write']
        }
        
        m.post(
            f"{self.base_url}/api/api-keys/",
            json=mock_api_key,
            status_code=201
        )
        
        api_key = self.client.create_api_key(
            name='Test API Key',
            scopes=['read', 'write'],
            expires_at='2024-01-01T00:00:00Z'
        )
        
        self.assertEqual(api_key['name'], 'Test API Key')
        self.assertEqual(api_key['key'], 'sk_test_123456789')
        self.assertEqual(api_key['scopes'], ['read', 'write'])
        
        # Test listing API keys
        m.get(
            f"{self.base_url}/api/api-keys/",
            json={'results': [mock_api_key]},
            status_code=200
        )
        
        api_keys = self.client.list_api_keys()
        self.assertEqual(len(api_keys), 1)
        self.assertEqual(api_keys[0]['name'], 'Test API Key')
        
        # Test revoking API key
        m.delete(
            f"{self.base_url}/api/api-keys/key-uuid-123/",
            json={'message': 'API key revoked successfully'},
            status_code=200
        )
        
        result = self.client.revoke_api_key('key-uuid-123')
        self.assertIn('message', result)
    
    @requests_mock.Mocker()
    def test_permission_checking(self, m):
        """Test permission checking functionality"""
        # Set up authenticated client
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        # Mock permissions response
        mock_permissions = [
            'users.view_own',
            'users.change_own',
            'api_keys.view_own',
            'api_keys.manage_own'
        ]
        
        m.get(
            f"{self.base_url}/api/auth/permissions/",
            json={'permissions': mock_permissions},
            status_code=200
        )
        
        permissions = self.client.get_my_permissions()
        self.assertIn('users.view_own', permissions)
        self.assertIn('api_keys.manage_own', permissions)
        
        # Test specific permission check
        self.assertTrue(self.client.has_permission('users.view_own'))
        self.assertFalse(self.client.has_permission('admin.manage_all'))
    
    @requests_mock.Mocker()
    def test_avatar_upload(self, m):
        """Test avatar file upload"""
        # Set up authenticated client
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        # Mock upload response
        updated_profile = self.mock_profile.copy()
        updated_profile['avatar'] = '/media/avatars/new_avatar.jpg'
        
        m.post(
            f"{self.base_url}/api/users/avatar/",
            json=updated_profile,
            status_code=200
        )
        
        # Create temporary image file
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(b'fake_image_data')
            temp_file_path = temp_file.name
        
        try:
            profile = self.client.upload_avatar(temp_file_path)
            self.assertEqual(profile['avatar'], '/media/avatars/new_avatar.jpg')
            
            # Verify multipart form upload
            req = m.request_history[0]
            self.assertIn('multipart/form-data', req.headers['Content-Type'])
            
        finally:
            os.unlink(temp_file_path)
    
    @requests_mock.Mocker()
    def test_error_handling(self, m):
        """Test various error scenarios"""
        # Test authentication error
        m.post(
            f"{self.base_url}/api/auth/login/",
            json={'error': 'Invalid credentials'},
            status_code=401
        )
        
        with self.assertRaises(AuthenticationError):
            self.client.login('invalid@test.com', 'wrongpassword')
        
        # Test authorization error
        self.client.session_manager.set_tokens(
            self.mock_tokens['access'],
            self.mock_tokens['refresh']
        )
        
        m.get(
            f"{self.base_url}/api/admin/users/",
            json={'error': 'Permission denied'},
            status_code=403
        )
        
        with self.assertRaises(AuthorizationError):
            self.client._make_request('GET', '/api/admin/users/')
        
        # Test validation error
        m.post(
            f"{self.base_url}/api/auth/register/",
            json={
                'email': ['Invalid email format'],
                'password': ['Password too weak']
            },
            status_code=400
        )
        
        with self.assertRaises(ValidationError):
            self.client.register('invalid-email', 'weak', 'Test', 'User')
        
        # Test rate limiting
        m.post(
            f"{self.base_url}/api/auth/login/",
            json={'error': 'Rate limit exceeded'},
            status_code=429,
            headers={'Retry-After': '60'}
        )
        
        with self.assertRaises(AuthlyError) as context:
            self.client.login(self.test_user['email'], self.test_user['password'])
        
        self.assertIn('rate limit', str(context.exception).lower())
    
    @requests_mock.Mocker()
    def test_session_persistence(self, m):
        """Test session token persistence across client instances"""
        # Login with first client instance
        m.post(
            f"{self.base_url}/api/auth/login/",
            json={
                'access': self.mock_tokens['access'],
                'refresh': self.mock_tokens['refresh'],
                'user': {'id': '123', 'email': 'test@example.com'}
            },
            status_code=200
        )
        
        self.client.login(
            email=self.test_user['email'],
            password=self.test_user['password']
        )
        
        # Create new client instance with same session file
        client2 = AuthlyClient(
            base_url=self.base_url,
            tenant=self.tenant,
            session_file=self.temp_session_file.name
        )
        
        # Should be authenticated without login
        self.assertTrue(client2.is_authenticated())
        self.assertEqual(
            client2.session_manager.get_access_token(),
            self.mock_tokens['access']
        )
    
    @requests_mock.Mocker()
    def test_token_refresh(self, m):
        """Test automatic token refresh"""
        # Set up client with expired access token
        expired_access_token = 'expired_token'
        self.client.session_manager.set_tokens(
            expired_access_token,
            self.mock_tokens['refresh']
        )
        
        # Mock refresh token response
        new_tokens = {
            'access': 'new_access_token_123',
            'refresh': 'new_refresh_token_456'
        }
        
        m.post(
            f"{self.base_url}/api/auth/refresh/",
            json=new_tokens,
            status_code=200
        )
        
        # Mock profile request that triggers refresh
        m.get(
            f"{self.base_url}/api/users/profile/",
            [
                {'json': {'error': 'Token expired'}, 'status_code': 401},  # First attempt
                {'json': self.mock_profile, 'status_code': 200}  # After refresh
            ]
        )
        
        # This should automatically refresh the token
        profile = self.client.get_profile()
        
        # Verify profile was retrieved successfully
        self.assertEqual(profile['email'], self.test_user['email'])
        
        # Verify new tokens are stored
        self.assertEqual(
            self.client.session_manager.get_access_token(),
            new_tokens['access']
        )
    
    def test_client_context_manager(self):
        """Test client usage as context manager"""
        with AuthlyClient(
            base_url=self.base_url,
            tenant=self.tenant
        ) as client:
            self.assertIsInstance(client, AuthlyClient)
            # Session should be cleaned up automatically on exit

class TestSDKIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""
    
    @requests_mock.Mocker()
    def test_complete_user_workflow(self, m):
        """Test complete user workflow: register -> login -> profile -> API key"""
        client = AuthlyClient(
            base_url="https://test.authly.com",
            tenant="test",
            debug=True
        )
        
        # 1. Register
        m.post(
            "https://test.authly.com/api/auth/register/",
            json={'message': 'Registration successful', 'user_id': 'user-123'},
            status_code=201
        )
        
        register_result = client.register(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        
        self.assertIn('message', register_result)
        
        # 2. Login
        m.post(
            "https://test.authly.com/api/auth/login/",
            json={
                'access': 'access_token_123',
                'refresh': 'refresh_token_123',
                'user': {'id': 'user-123', 'email': 'test@example.com'}
            },
            status_code=200
        )
        
        tokens = client.login('test@example.com', 'TestPassword123!')
        self.assertTrue(client.is_authenticated())
        
        # 3. Get profile
        m.get(
            "https://test.authly.com/api/users/profile/",
            json={
                'id': 'user-123',
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User'
            },
            status_code=200
        )
        
        profile = client.get_profile()
        self.assertEqual(profile['email'], 'test@example.com')
        
        # 4. Create API key
        m.post(
            "https://test.authly.com/api/api-keys/",
            json={
                'id': 'key-123',
                'name': 'Test Key',
                'key': 'sk_test_123',
                'created_at': '2023-01-01T00:00:00Z'
            },
            status_code=201
        )
        
        api_key = client.create_api_key(name='Test Key')
        self.assertEqual(api_key['name'], 'Test Key')

def run_tests():
    """Run the test suite"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestAuthlySDK))
    test_suite.addTest(unittest.makeSuite(TestSDKIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    print("🧪 Running Authly SDK Test Suite")
    print("=" * 50)
    
    success = run_tests()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed! SDK is working correctly.")
    else:
        print("❌ Some tests failed. Please check the output above.")
    
    sys.exit(0 if success else 1)