# authly_api/urls_public.py
from django.urls import path
from django.http import HttpResponse

def public_home(request):
    return HttpResponse("Welcome to the public schema")

urlpatterns = [
    path('', public_home),
]