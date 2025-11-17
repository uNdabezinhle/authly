from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema, extend_schema_view
from apps.roles.permissions import permission_required, check_permission
from .models import User
from .serializers import (
    UserProfileSerializer, 
    ProfileUpdateSerializer,
    PasswordChangeSerializer,
    AvatarUploadSerializer
)


@extend_schema_view(
    me=extend_schema(
        summary="Get current user profile",
        description="Get the authenticated user's profile information",
        responses={200: UserProfileSerializer}
    ),
    update_profile=extend_schema(
        summary="Update user profile",
        description="Update the authenticated user's profile information",
        request=ProfileUpdateSerializer,
        responses={200: UserProfileSerializer}
    ),
    change_password=extend_schema(
        summary="Change user password",
        description="Change the authenticated user's password",
        request=PasswordChangeSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}}
    ),
    upload_avatar=extend_schema(
        summary="Upload user avatar",
        description="Upload or update the authenticated user's avatar image",
        request=AvatarUploadSerializer,
        responses={200: UserProfileSerializer}
    )
)
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return super().get_queryset().filter(tenant=self.request.tenant)

    def get_serializer_class(self):
        if self.action == 'update_profile':
            return ProfileUpdateSerializer
        elif self.action == 'change_password':
            return PasswordChangeSerializer
        elif self.action == 'upload_avatar':
            return AvatarUploadSerializer
        return UserProfileSerializer

    @action(detail=False, methods=['get'], url_path='me')
    @permission_required('users.view_profile')
    def me(self, request):
        """Get current user profile"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['patch'], url_path='profile')
    @permission_required('users.change_profile')
    def update_profile(self, request):
        """Update user profile information"""
        serializer = self.get_serializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Return updated profile using profile serializer
        profile_serializer = UserProfileSerializer(request.user, context={'request': request})
        return Response(profile_serializer.data)

    @action(detail=False, methods=['post'], url_path='change-password')
    @permission_required('users.change_password')
    def change_password(self, request):
        """Change user password"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response(
            {"message": "Password changed successfully."}, 
            status=status.HTTP_200_OK
        )

    @action(
        detail=False, 
        methods=['post'], 
        url_path='upload-avatar',
        parser_classes=[MultiPartParser, FormParser]
    )
    @permission_required('users.change_profile')
    def upload_avatar(self, request):
        """Upload or update user avatar"""
        serializer = self.get_serializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Return updated profile
        profile_serializer = UserProfileSerializer(request.user, context={'request': request})
        return Response(profile_serializer.data)
