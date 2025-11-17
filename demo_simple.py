#!/usr/bin/env python3
"""
Simple Authly SDK Demo
Shows basic usage patterns for the Authly Python SDK
"""

from authly_client_sdk import AuthlyClient, AuthlyError

def simple_demo():
    """Simple demonstration of SDK usage"""
    
    print("🚀 Authly SDK - Simple Demo")
    print("=" * 40)
    
    # Initialize client
    client = AuthlyClient(
        base_url="http://localhost:8000",  # Your API URL
        tenant="test",  # Your tenant slug
        debug=False
    )
    
    print(f"✅ Client initialized")
    print(f"📡 API URL: {client.base_url}")
    print(f"🏢 Tenant: {client.tenant}")
    
    # Example 1: Check if authenticated
    if client.is_authenticated():
        print("🔐 Already authenticated!")
        
        try:
            # Get user profile
            profile = client.get_profile()
            print(f"👤 Welcome back, {profile['first_name']}!")
            
            # Check permissions
            permissions = client.get_my_permissions()
            print(f"🔑 You have {len(permissions)} permissions")
            
            # List API keys
            api_keys = client.list_api_keys()
            print(f"🗝️ You have {len(api_keys)} API keys")
            
        except AuthlyError as e:
            print(f"❌ Error: {e}")
    
    else:
        print("🔓 Not authenticated")
        print("💡 To use this demo:")
        print("   1. Login to your Authly instance")
        print("   2. Run: client.login('email', 'password')")
        print("   3. Or use the interactive demo: python authly_client_sdk.py demo")

if __name__ == "__main__":
    simple_demo()