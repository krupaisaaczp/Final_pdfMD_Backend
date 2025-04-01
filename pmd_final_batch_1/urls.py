from django.urls import path, include
from django.http import HttpResponse
from rest_framework.routers import DefaultRouter
from .views import (
    PDFFileViewSet, register_user, login_user, token_auth, user_profile,
    analyze_pdf, get_analysis_results, analysis_history, download_report
)

router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')

urlpatterns = [
    path('', lambda request: HttpResponse('OK'), name='health'),
    path('api/', include(router.urls)),
    path('api/auth/register/', register_user, name='register'),
    path('api/auth/login/', login_user, name='login'),
    path('api/token-auth/', token_auth, name='token-auth'),
    path('api/user-profile/', user_profile, name='user-profile'),
    path('api/analyze-pdf/', analyze_pdf, name='analyze-pdf'),
    path('api/analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
    path('api/analysis-history/', analysis_history, name='analysis-history'),
    path('api/download-report/<int:pdf_id>/', download_report, name='download-report'),
]