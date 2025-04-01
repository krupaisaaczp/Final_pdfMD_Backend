from django.db import models
from django.contrib.auth.models import User

class PDFFile(models.Model):
    file = models.FileField(upload_to='pdfs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_malicious = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='pdf_files', null=True)
    prediction_confidence = models.FloatField(default=0.0)
    report_file = models.FileField(upload_to='reports/', null=True, blank=True)
    
    def __str__(self):
        return self.file.name

class AnalysisResult(models.Model):
    pdf_file = models.OneToOneField(PDFFile, on_delete=models.CASCADE, related_name='analysis')
    features = models.JSONField(default=dict)
    explanation = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Analysis for {self.pdf_file.file.name}"