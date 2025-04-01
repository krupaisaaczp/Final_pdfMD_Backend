from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PDFFileViewSet, register_user, login_user, token_auth, user_profile,
    analyze_pdf, get_analysis_results, analysis_history, download_report
)

router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')  # Changed to 'pdfs' (no 'api/' prefix here)

urlpatterns = [
    path('', include(router.urls)),  # Handles /pdfs/ endpoints
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('token-auth/', token_auth, name='token-auth'),
    path('user-profile/', user_profile, name='user-profile'),
    path('analyze-pdf/', analyze_pdf, name='analyze-pdf'),
    path('analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
    path('analysis-history/', analysis_history, name='analysis-history'),
    path('download-report/<int:pdf_id>/', download_report, name='download-report'),
]