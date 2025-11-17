import jwt
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

from .models import TokenScope, ScopedToken, TokenIntrospection
from apps.tenants.models import Tenant

User = get_user_model()


class TokenScopeModelTest(TestCase):
    def setUp(self):
        self.scope = TokenScope.objects.create(
            name='users.read',
            description='Read user information',
            resource_type='users',
            actions=['read'],
            max_token_lifetime=3600
        )
    
    def test_string_representation(self):
        expected = "users.read (users)"
        self.assertEqual(str(self.scope), expected)
    
    def test_scope_constraints(self):
        self.assertFalse(self.scope.is_sensitive)
        self.assertFalse(self.scope.requires_mfa)
        self.assertEqual(self.scope.max_token_lifetime, 3600)


class ScopedTokenModelTest(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(
            schema_name='test',
            name='Test Tenant'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            tenant=self.tenant
        )
        self.scope = TokenScope.objects.create(
            name='users.read',
            description='Read users',
            resource_type='users',
            actions=['read']
        )
        self.token = ScopedToken.objects.create(
            user=self.user,
            tenant=self.tenant,
            jti='test-jti-123',
            token_type='access',
            audience='test-api',
            expires_at=timezone.now() + timedelta(hours=1),
            permissions=['users.read']
        )
        self.token.scopes.add(self.scope)
    
    def test_string_representation(self):
        expected = f"access token for {self.user.email} (test-jti...)"
        self.assertEqual(str(self.token), expected)
    
    def test_token_validity(self):
        self.assertTrue(self.token.is_valid())
    
    def test_expired_token(self):
        self.token.expires_at = timezone.now() - timedelta(hours=1)
        self.token.save()
        self.assertFalse(self.token.is_valid())
    
    def test_revoked_token(self):
        self.token.revoke(reason='Test revocation')
        self.assertFalse(self.token.is_valid())
        self.assertFalse(self.token.is_active)
        self.assertIsNotNone(self.token.revoked_at)
    
    def test_usage_tracking(self):
        initial_count = self.token.usage_count
        self.token.record_usage('192.168.1.1')
        self.assertEqual(self.token.usage_count, initial_count + 1)
        self.assertEqual(self.token.last_used_ip, '192.168.1.1')
        self.assertIsNotNone(self.token.last_used_at)
    
    def test_scope_operations(self):
        self.assertTrue(self.token.has_scope('users.read'))
        self.assertFalse(self.token.has_scope('users.write'))
        self.assertIn('users.read', self.token.get_scope_names())
    
    def test_permission_check(self):
        self.assertTrue(self.token.has_permission('users.read'))
        self.assertFalse(self.token.has_permission('users.delete'))
    
    def test_jwt_generation(self):
        jwt_token = self.token.generate_jwt()
        self.assertIsInstance(jwt_token, str)
        
        # Decode and verify claims
        payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
        self.assertEqual(payload['jti'], self.token.jti)
        self.assertEqual(payload['sub'], str(self.user.id))
        self.assertEqual(payload['aud'], self.token.audience)
        self.assertEqual(payload['tenant_id'], str(self.tenant.id))
        self.assertEqual(payload['scopes'], ['users.read'])
        self.assertEqual(payload['permissions'], ['users.read'])
    
    def test_max_uses_constraint(self):
        self.token.max_uses = 2
        self.token.save()
        
        # Use token twice
        self.token.record_usage()
        self.token.record_usage()
        
        # Should still be valid at exactly max uses
        self.assertTrue(self.token.is_valid())
        
        # One more use should make it invalid
        self.token.record_usage()
        self.assertFalse(self.token.is_valid())