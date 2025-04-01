from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PDFFileViewSet

# Create a router and register the PDFFileViewSet
router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')  # ✅ Use "pdfs" instead of "pdf"

# Include router-generated URLs
urlpatterns = [
    path('api/', include(router.urls)),  # ✅ Ensure the correct API prefix
]
