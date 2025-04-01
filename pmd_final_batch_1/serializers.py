from rest_framework import serializers
from django.contrib.auth.models import User
from .models import PDFFile, AnalysisResult

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']  # Added password field here
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password']
        )
        return user

class AnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisResult
        fields = ['features', 'explanation', 'created_at']

class PDFFileSerializer(serializers.ModelSerializer):
    analysis = AnalysisResultSerializer(read_only=True)
    
    class Meta:
        model = PDFFile
        fields = ['id', 'file', 'uploaded_at', 'is_malicious', 'prediction_confidence', 'report_file', 'analysis']