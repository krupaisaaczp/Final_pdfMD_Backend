from rest_framework import serializers
from .models import PDFFile  # Ensure models.py exists

class PDFFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = PDFFile
        fields = "__all__"
