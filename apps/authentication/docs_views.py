# apps/authentication/docs_views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from .serializers import LoginSerializer

@extend_schema(
    summary="Swagger UI JWT Login",
    description="Login endpoint specifically designed for Swagger UI authentication. Use the returned access token in the 'Authorize' button.",
    request=LoginSerializer,
    responses={
        200: {
            'description': 'Login successful',
            'content': {
                'application/json': {
                    'examples': {
                        'success': OpenApiExample(
                            name='Success Response',
                            value={
                                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                                'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                                'user': {
                                    'id': 'uuid-string',
                                    'email': 'user@example.com',
                                    'first_name': 'John',
                                    'last_name': 'Doe'
                                },
                                'instructions': 'Copy the access_token and click the Authorize button above. Paste the token in the value field.'
                            }
                        )
                    }
                }
            }
        },
        400: {
            'description': 'Login failed',
            'content': {
                'application/json': {
                    'examples': {
                        'error': OpenApiExample(
                            name='Error Response',
                            value={
                                'error': 'Invalid credentials or account not verified'
                            }
                        )
                    }
                }
            }
        }
    },
    tags=['Swagger UI Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def swagger_login(request):
    """
    JWT Login for Swagger UI
    
    This endpoint is specifically designed for authenticating in the Swagger UI.
    After successful login:
    1. Copy the 'access_token' from the response
    2. Click the 'Authorize' button at the top of this page
    3. Paste the token in the 'Bearer' field
    4. You'll now be able to test authenticated endpoints
    
    Note: This endpoint doesn't create session records for simplicity.
    """
    serializer = LoginSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({
            'error': 'Invalid input',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = serializer.validated_data['user']
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        return Response({
            'access_token': str(access),
            'refresh_token': str(refresh),
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'mfa_enabled': user.mfa_enabled,
            },
            'instructions': 'Copy the access_token above and click the Authorize button. Paste the token in the Bearer field.',
            'expires_in': 900  # 15 minutes
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': 'Authentication failed',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    summary="API Test Endpoint",
    description="Test endpoint to verify JWT authentication is working in Swagger UI",
    responses={
        200: {
            'description': 'Authentication successful',
            'content': {
                'application/json': {
                    'examples': {
                        'success': OpenApiExample(
                            name='Success Response',
                            value={
                                'message': 'JWT authentication is working!',
                                'user': 'user@example.com',
                                'tenant': 'example-tenant'
                            }
                        )
                    }
                }
            }
        },
        401: {
            'description': 'Authentication required',
            'content': {
                'application/json': {
                    'examples': {
                        'error': OpenApiExample(
                            name='Error Response',
                            value={
                                'detail': 'Authentication credentials were not provided.'
                            }
                        )
                    }
                }
            }
        }
    },
    tags=['Swagger UI Authentication']
)
@api_view(['GET'])
def test_auth(request):
    """
    Test JWT Authentication
    
    This endpoint requires JWT authentication. Use it to test that your 
    JWT token from the swagger_login endpoint is working correctly.
    
    If you see a 401 error:
    1. Make sure you've logged in using the swagger_login endpoint
    2. Copy the access_token from the login response
    3. Click the 'Authorize' button and paste the token
    4. Try this endpoint again
    """
    return Response({
        'message': 'JWT authentication is working!',
        'user': request.user.email,
        'tenant': request.tenant.slug if hasattr(request, 'tenant') and request.tenant else 'No tenant',
        'token_info': {
            'user_id': str(request.user.id),
            'is_authenticated': request.user.is_authenticated,
            'permissions': list(request.user.get_permissions()) if hasattr(request.user, 'get_permissions') else []
        }
    }, status=status.HTTP_200_OK)