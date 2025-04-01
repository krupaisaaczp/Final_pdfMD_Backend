from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PDFFileViewSet, register_user, login_user, get_analysis_results

router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
]