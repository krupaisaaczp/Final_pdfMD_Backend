from django.urls import path
from .views import PDFUploadView  # Ensure correct import

urlpatterns = [
    path('upload/', PDFUploadView.as_view(), name='pdf-upload'),
]
