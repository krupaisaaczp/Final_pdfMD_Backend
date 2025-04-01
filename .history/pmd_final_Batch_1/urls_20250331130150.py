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
    path('api/auth/register/', register_user, name='register'),
    path('api/auth/login/', login_user, name='login'),
    path('api/token-auth/', token_auth, name='token-auth'),
    path('api/user-profile/', user_profile, name='user-profile'),
    path('api/analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
    path('api/analyze-pdf/', analyze_pdf, name='analyze-pdf'),
    path('api/analysis-history/', analysis_history, name='analysis-history'),
    path('api/analysis-details/<int:pdf_id>/', get_analysis_results, name='analysis-details'),
]