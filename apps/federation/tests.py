from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import IdentityProvider, FederatedUser, SAMLSession

User = get_user_model()


class IdentityProviderModelTest(TestCase):
    def setUp(self):
        self.idp = IdentityProvider.objects.create(
            name="Test SAML Provider",
            slug="test-saml",
            provider_type="saml",
            entity_id="https://idp.example.com/metadata",
            sso_url="https://idp.example.com/sso",
            jit_enabled=True
        )
    
    def test_string_representation(self):
        self.assertEqual(str(self.idp), "Test SAML Provider (SAML)")
    
    def test_jit_provisioning_enabled(self):
        self.assertTrue(self.idp.jit_enabled)


class FederatedUserModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com"
        )
        self.idp = IdentityProvider.objects.create(
            name="Test Provider",
            slug="test-provider", 
            provider_type="oidc"
        )
        self.federated_user = FederatedUser.objects.create(
            user=self.user,
            identity_provider=self.idp,
            external_user_id="ext123",
            external_email="test@example.com"
        )
    
    def test_string_representation(self):
        expected = "test@example.com via Test Provider"
        self.assertEqual(str(self.federated_user), expected)
    
    def test_unique_constraint(self):
        # Should not be able to create another federated user with same external_user_id for same IdP
        with self.assertRaises(Exception):
            FederatedUser.objects.create(
                user=self.user,
                identity_provider=self.idp,
                external_user_id="ext123",  # Same external ID
                external_email="other@example.com"
            )