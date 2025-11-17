from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'federation'

router = DefaultRouter()
router.register(r'identity-providers', views.IdentityProviderViewSet)
router.register(r'federated-users', views.FederatedUserViewSet)

urlpatterns = [
    path('api/v1/', include(router.urls)),
    
    # SSO Initiation
    path('api/v1/sso/<str:tenant_slug>/<str:idp_slug>/init/', 
         views.initiate_sso, 
         name='initiate_sso'),
    
    # SAML Endpoints
    path('api/v1/sso/<str:tenant_slug>/<str:idp_slug>/saml/acs/', 
         views.saml_acs, 
         name='saml_acs'),
    
    # OIDC Endpoints  
    path('api/v1/sso/<str:tenant_slug>/<str:idp_slug>/oidc/callback/', 
         views.oidc_callback, 
         name='oidc_callback'),
]