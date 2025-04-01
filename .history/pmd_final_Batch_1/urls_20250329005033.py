from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PDFFileViewSet

# Create a router and register the PDFFileViewSet
router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')  # ✅ Ensure the correct name

urlpatterns = [
    path('', include(router.urls)),  # ✅ This ensures API endpoints work
]
