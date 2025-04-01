# pmd_final_batch_1/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PDFFileViewSet, register_user, login_user, token_auth,
    user_profile, get_analysis_results, analyze_pdf, analysis_history
)

router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('token-auth/', token_auth, name='token-auth'),  # Added for frontend compatibility
    path('register/', register_user, name='register-alt'),  # Added for frontend compatibility
    path('user-profile/', user_profile, name='user-profile'),
    path('analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
    path('analyze-pdf/', analyze_pdf, name='analyze-pdf'),
    path('analysis-history/', analysis_history, name='analysis-history'),
    path('analysis-details/<int:pdf_id>/', get_analysis_results, name='analysis-details'),
]