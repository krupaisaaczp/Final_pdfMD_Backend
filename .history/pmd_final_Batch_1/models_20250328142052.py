from django.db import models

class PDFFile(models.Model):
    file = models.FileField(upload_to='pdfs/')  # Upload PDFs to 'media/pdfs/'
    uploaded_at = models.DateTimeField(auto_now_add=True)  # Store upload time
    is_malicious = models.BooleanField(default=False)  # Store malware detection result

    def __str__(self):
        return self.file.name
