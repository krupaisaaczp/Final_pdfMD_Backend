from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PDFFileViewSet

# Create a router and register our viewset with the correct prefix
router = DefaultRouter()
router.register(r'pdf', PDFFileViewSet, basename='pdf')

# The API URLs are now determined automatically by the router.
urlpatterns = [
    path('api/', include(router.urls)),  # Ensure 'api/' is in the path
]
