from django.urls import path
from .views import PDFUploadView  # Import your view

urlpatterns = [
    path("pdfs/", PDFUploadView.as_view(), name="pdf-upload"),
]
