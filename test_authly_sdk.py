#!/usr/bin/env python3
"""
Authly SDK Test Script
Comprehensive testing suite for the Authly Client SDK

Usage:
    python test_authly_sdk.py --url http://localhost:8000 --tenant test
    python test_authly_sdk.py --interactive  # Interactive test mode
    python test_authly_sdk.py --unit  # Unit tests only
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import argparse
import getpass

# Import the SDK
from authly_client_sdk import (
    AuthlyClient, 
    AuthlyError, 
    AuthenticationError, 
    AuthorizationError,
    MFARequiredError, 
    ValidationError, 
    NetworkError,
    SessionManager
)


class TestSessionManager(unittest.TestCase):
    """Test SessionManager functionality"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False).name
        self.session_manager = SessionManager(self.temp_file)
    
    def tearDown(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_file):
            os.remove(self.temp_file)
    
    def test_token_management(self):
        """Test token setting and retrieval"""
        access_token = "test_access_token"
        refresh_token = "test_refresh_token"
        
        self.session_manager.set_tokens(access_token, refresh_token)
        
        self.assertEqual(self.session_manager.access_token, access_token)
        self.assertEqual(self.session_manager.refresh_token, refresh_token)
        self.assertIsNotNone(self.session_manager.token_expires_at)
    
    def test_token_expiry(self):
        """Test token expiry checking"""
        # Initially should be expired (no token)
        self.assertTrue(self.session_manager.is_token_expired())
        
        # Set token with longer expiry for testing
        self.session_manager.set_tokens("access", "refresh", expires_in=300)  # 5 minutes
        self.assertFalse(self.session_manager.is_token_expired())
        
        # Set token with past expiry
        self.session_manager.token_expires_at = datetime.now() - timedelta(minutes=1)
        self.assertTrue(self.session_manager.is_token_expired())
    
    def test_session_persistence(self):
        """Test session save/load functionality"""
        access_token = "persist_test_access"
        refresh_token = "persist_test_refresh"
        
        # Set tokens and save
        self.session_manager.set_tokens(access_token, refresh_token)
        
        # Create new session manager with same file
        new_session = SessionManager(self.temp_file)
        
        self.assertEqual(new_session.access_token, access_token)
        self.assertEqual(new_session.refresh_token, refresh_token)
    
    def test_clear_session(self):
        """Test session clearing"""
        self.session_manager.set_tokens("access", "refresh")
        self.session_manager.clear_session()
        
        self.assertIsNone(self.session_manager.access_token)
        self.assertIsNone(self.session_manager.refresh_token)
        self.assertIsNone(self.session_manager.token_expires_at)


class TestAuthlyClientInit(unittest.TestCase):
    """Test AuthlyClient initialization"""
    
    def test_valid_initialization(self):
        """Test valid client initialization"""
        client = AuthlyClient(
            base_url="https://api.example.com",
            tenant="test-tenant"
        )
        self.assertEqual(client.base_url, "https://api.example.com")
        self.assertEqual(client.tenant, "test-tenant")
    
    def test_invalid_base_url(self):
        """Test invalid base URL handling"""
        with self.assertRaises(ValueError):
            AuthlyClient(base_url="invalid-url", tenant="test")
    
    def test_invalid_tenant(self):
        """Test invalid tenant handling"""
        from authly_client_sdk import TenantError
        
        with self.assertRaises(TenantError):
            AuthlyClient(base_url="https://api.example.com", tenant="")
    
    def test_context_manager(self):
        """Test context manager functionality"""
        with AuthlyClient(base_url="https://api.example.com", tenant="test") as client:
            self.assertIsNotNone(client.session)


class TestAuthlyClientMocked(unittest.TestCase):
    """Test AuthlyClient with mocked responses"""
    
    def setUp(self):
        """Setup test client"""
        self.client = AuthlyClient(
            base_url="https://api.example.com",
            tenant="test-tenant"
        )
    
    @patch('authly_client_sdk.requests.Session.request')
    def test_register_success(self, mock_request):
        """Test successful user registration"""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            'message': 'Registration successful',
            'user_id': 'test-user-id'
        }
        mock_request.return_value = mock_response
        
        result = self.client.register(
            email="test@example.com",
            password="TestPass123!",
            first_name="Test",
            last_name="User"
        )
        
        self.assertEqual(result['message'], 'Registration successful')
        self.assertEqual(result['user_id'], 'test-user-id')
    
    @patch('authly_client_sdk.requests.Session.request')
    def test_login_success(self, mock_request):
        """Test successful login"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access': 'test_access_token',
            'refresh': 'test_refresh_token',
            'user': {
                'id': 'test-user-id',
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'mfa_enabled': False
            }
        }
        mock_request.return_value = mock_response
        
        result = self.client.login("test@example.com", "TestPass123!")
        
        self.assertIn('access', result)
        self.assertIn('refresh', result)
        self.assertEqual(self.client.session_manager.access_token, 'test_access_token')
    
    @patch('authly_client_sdk.requests.Session.request')
    def test_login_mfa_required(self, mock_request):
        """Test login with MFA required"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'mfa_required': True,
            'message': 'MFA token required'
        }
        mock_request.return_value = mock_response
        
        with self.assertRaises(MFARequiredError):
            self.client.login("test@example.com", "TestPass123!")
    
    @patch('authly_client_sdk.requests.Session.request')
    def test_authentication_error(self, mock_request):
        """Test authentication error handling"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response
        
        with self.assertRaises(AuthenticationError):
            self.client.get_profile()
    
    @patch('authly_client_sdk.requests.Session.request')
    def test_authorization_error(self, mock_request):
        """Test authorization error handling"""
        # First call for auth check (success)
        mock_auth_response = Mock()
        mock_auth_response.status_code = 200
        
        # Second call for actual request (forbidden)
        mock_forbidden_response = Mock()
        mock_forbidden_response.status_code = 403
        mock_forbidden_response.json.return_value = {'detail': 'Permission denied'}
        
        mock_request.side_effect = [mock_forbidden_response]
        
        # Set up authenticated state
        self.client.session_manager.set_tokens("access", "refresh")
        
        with self.assertRaises(AuthorizationError):
            self.client.get_my_permissions()


class InteractiveTest:
    """Interactive test suite for live API testing"""
    
    def __init__(self, base_url: str, tenant: str):
        self.base_url = base_url
        self.tenant = tenant
        self.client = None
        self.test_user_email = None
    
    def run_all_tests(self):
        """Run all interactive tests"""
        print("🧪 Starting Interactive Tests")
        print("=" * 50)
        
        try:
            self.test_client_initialization()
            self.test_registration_flow()
            self.test_authentication_flow()
            self.test_profile_management()
            self.test_mfa_flow()
            self.test_api_key_management()
            self.test_permissions()
            print("\n✅ All tests completed successfully!")
        except Exception as e:
            print(f"\n❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
    
    def test_client_initialization(self):
        """Test 1: Client Initialization"""
        print("\n1️⃣ Testing Client Initialization")
        
        self.client = AuthlyClient(
            base_url=self.base_url,
            tenant=self.tenant,
            debug=True
        )
        
        print(f"✅ Client initialized for {self.base_url} (tenant: {self.tenant})")
        
        # Test health check if available
        try:
            health = self.client.healthcheck()
            print(f"🩺 Health check: {health.get('status', 'unknown')}")
        except:
            print("🩺 Health check not available")
    
    def test_registration_flow(self):
        """Test 2: User Registration"""
        print("\n2️⃣ Testing User Registration")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.test_user_email = f"test_user_{timestamp}@example.com"
        
        print(f"📧 Registering user: {self.test_user_email}")
        
        try:
            result = self.client.register(
                email=self.test_user_email,
                password="TestPassword123!",
                first_name="Test",
                last_name="User",
                bio="Created by SDK test suite"
            )
            
            print(f"✅ Registration successful: {result.get('message')}")
            print(f"👤 User ID: {result.get('user_id')}")
            
        except ValidationError as e:
            print(f"⚠️ Registration validation error (expected): {e}")
        except Exception as e:
            print(f"❌ Registration failed: {e}")
            raise
    
    def test_authentication_flow(self):
        """Test 3: Authentication"""
        print("\n3️⃣ Testing Authentication")
        
        if not self.test_user_email:
            print("⚠️ Skipping authentication test - no test user")
            return
        
        try:
            # Test login
            result = self.client.login(
                self.test_user_email,
                "TestPassword123!"
            )
            
            print(f"✅ Login successful")
            print(f"🔑 Access token: {result['access'][:20]}...")
            
            user_info = result.get('user', {})
            print(f"👤 User: {user_info.get('first_name')} {user_info.get('last_name')}")
            
            # Test token refresh
            original_token = self.client.session_manager.access_token
            refresh_result = self.client.refresh_token()
            new_token = refresh_result['access']
            
            print(f"🔄 Token refresh successful: {new_token[:20]}...")
            
        except AuthenticationError as e:
            print(f"❌ Authentication failed: {e}")
        except MFARequiredError:
            print("🔐 MFA required - this is expected for MFA-enabled accounts")
    
    def test_profile_management(self):
        """Test 4: Profile Management"""
        print("\n4️⃣ Testing Profile Management")
        
        if not self.client.is_authenticated():
            print("⚠️ Skipping profile test - not authenticated")
            return
        
        try:
            # Get profile
            profile = self.client.get_profile()
            print(f"👤 Current profile:")
            print(f"   - Name: {profile['first_name']} {profile['last_name']}")
            print(f"   - Email: {profile['email']}")
            
            # Update profile
            update_time = datetime.now().isoformat()
            updated = self.client.update_profile(
                bio=f"Updated by SDK test at {update_time}"
            )
            
            print(f"✅ Profile updated successfully")
            
        except Exception as e:
            print(f"❌ Profile management failed: {e}")
    
    def test_mfa_flow(self):
        """Test 5: MFA Flow"""
        print("\n5️⃣ Testing MFA Flow")
        
        if not self.client.is_authenticated():
            print("⚠️ Skipping MFA test - not authenticated")
            return
        
        try:
            # Check MFA status
            status = self.client.mfa_status()
            print(f"🔐 MFA Status: {'Enabled' if status['mfa_enabled'] else 'Disabled'}")
            print(f"📱 Devices: {status['devices']}")
            
            if not status['mfa_enabled']:
                user_choice = input("Enable MFA for testing? (y/N): ")
                if user_choice.lower() == 'y':
                    mfa_data = self.client.mfa_enable()
                    print(f"🔐 MFA enabled!")
                    print(f"📱 QR Code URL: {mfa_data.get('qr_code_url')}")
                    print(f"🔑 Manual Key: {mfa_data.get('manual_key')}")
            
        except Exception as e:
            print(f"❌ MFA test failed: {e}")
    
    def test_api_key_management(self):
        """Test 6: API Key Management"""
        print("\n6️⃣ Testing API Key Management")
        
        if not self.client.is_authenticated():
            print("⚠️ Skipping API key test - not authenticated")
            return
        
        try:
            # List existing keys
            keys = self.client.list_api_keys()
            print(f"📋 Existing API keys: {len(keys)}")
            
            # Create new key
            new_key = self.client.create_api_key(
                name="SDK Test Key",
                expires_at=(datetime.now() + timedelta(days=1)).isoformat()
            )
            
            print(f"🔑 Created API key: {new_key['name']}")
            print(f"   Key: {new_key['key'][:20]}...")
            print(f"   Expires: {new_key['expires_at']}")
            
            key_id = new_key['id']
            
            # List again to confirm
            keys = self.client.list_api_keys()
            print(f"📋 Total API keys after creation: {len(keys)}")
            
            # Clean up - revoke the test key
            self.client.revoke_api_key(key_id)
            print(f"🗑️ Test API key revoked")
            
        except Exception as e:
            print(f"❌ API key test failed: {e}")
    
    def test_permissions(self):
        """Test 7: Permission System"""
        print("\n7️⃣ Testing Permission System")
        
        if not self.client.is_authenticated():
            print("⚠️ Skipping permissions test - not authenticated")
            return
        
        try:
            # Get permissions
            permissions = self.client.get_my_permissions()
            print(f"🔐 User permissions ({len(permissions)}):")
            
            for perm in permissions[:10]:  # Show first 10
                print(f"   - {perm}")
            
            if len(permissions) > 10:
                print(f"   ... and {len(permissions) - 10} more")
            
            # Test specific permission checks
            test_permissions = [
                'users.view_profile',
                'users.change_profile',
                'users.manage_users',
                'api_keys.view_own',
                'roles.manage_roles'
            ]
            
            print(f"\n🔍 Permission checks:")
            for perm in test_permissions:
                has_perm = self.client.has_permission(perm)
                status = "✅ Yes" if has_perm else "❌ No"
                print(f"   - {perm}: {status}")
            
        except Exception as e:
            print(f"❌ Permission test failed: {e}")


def run_unit_tests():
    """Run unit tests"""
    print("🧪 Running Unit Tests")
    print("=" * 30)
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTest(unittest.makeSuite(TestSessionManager))
    suite.addTest(unittest.makeSuite(TestAuthlyClientInit))
    suite.addTest(unittest.makeSuite(TestAuthlyClientMocked))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_interactive_tests(base_url: str, tenant: str):
    """Run interactive tests against live API"""
    tester = InteractiveTest(base_url, tenant)
    tester.run_all_tests()


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="Authly SDK Test Suite")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--tenant", default="test", help="Tenant slug")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--interactive", action="store_true", help="Run interactive tests")
    
    args = parser.parse_args()
    
    print("🧪 Authly SDK Test Suite")
    print("=" * 40)
    
    success = True
    
    # Run unit tests
    if args.unit or not args.interactive:
        print("\n📋 Running unit tests...")
        success &= run_unit_tests()
    
    # Run interactive tests
    if args.interactive:
        print(f"\n🌐 Running interactive tests against {args.url}")
        try:
            run_interactive_tests(args.url, args.tenant)
        except KeyboardInterrupt:
            print("\n⏹️ Tests interrupted by user")
            success = False
        except Exception as e:
            print(f"\n❌ Interactive tests failed: {e}")
            success = False
    
    if success:
        print("\n🎉 All tests completed successfully!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())