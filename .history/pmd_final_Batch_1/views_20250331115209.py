
# pmd_final_batch_1/views.py
import os
import uuid
import json
from pathlib import Path
from django.conf import settings
from django.core.files.storage import default_storage
from django.contrib.auth import authenticate
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authtoken.models import Token

from .models import PDFFile, AnalysisResult
from .serializers import PDFFileSerializer, UserSerializer
from .ml_service import (
    preprocess_pdf, extract_features, preprocess_features,
    predict_malware, generate_report, explain_prediction
)

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': serializer.data
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    
    if user:
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        })
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class PDFFileViewSet(viewsets.ModelViewSet):
    serializer_class = PDFFileSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return PDFFile.objects.filter(user=self.request.user)
    
    def create(self, request, *args, **kwargs):
        if 'file' not in request.FILES:
            return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES['file']
        if not file.name.lower().endswith('.pdf'):
            return Response({"error": "File must be a PDF"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate unique filename
        filename = f"{uuid.uuid4()}_{file.name}"
        file_path = default_storage.save(f"pdfs/{filename}", file)
        absolute_file_path = Path(settings.MEDIA_ROOT) / file_path

        try:
            # Step 1: Extract Features
            raw_features = extract_features(str(absolute_file_path))
            features_json = json.dumps(raw_features)
            
            # Step 2: Preprocess Features
            processed_features = preprocess_features(raw_features)
            
            # Step 3: Predict Malware
            prediction_result = predict_malware(processed_features)
            is_malicious = prediction_result['prediction'].lower() == "malicious"
            confidence = prediction_result['confidence']
            
            # Step 4: Generate Report with Unique Filename
            report_filename = f"{uuid.uuid4()}_report.pdf"
            report_path = generate_report(str(absolute_file_path), report_filename)
            report_relative_path = os.path.relpath(report_path, settings.MEDIA_ROOT)
            
            # Step 5: Explain the Prediction
            explanation = explain_prediction(str(absolute_file_path), processed_features)
            
            # Step 6: Save to Database
            pdf_instance = PDFFile.objects.create(
                file=file_path, 
                is_malicious=is_malicious,
                prediction_confidence=confidence,
                report_file=report_relative_path,
                user=request.user
            )
            
            # Step 7: Create Analysis Result
            AnalysisResult.objects.create(
                pdf_file=pdf_instance,
                features=raw_features,
                explanation=explanation
            )

            return Response({
                "message": "File uploaded and analyzed successfully",
                "file_id": pdf_instance.id,
                "file_name": filename,
                "is_malicious": is_malicious,
                "confidence": confidence,
                "report_path": report_relative_path
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_analysis_results(request, pdf_id):
    try:
        pdf_file = PDFFile.objects.get(id=pdf_id, user=request.user)
        if not hasattr(pdf_file, 'analysis'):
            return Response({"error": "No analysis available for this file"}, status=status.HTTP_404_NOT_FOUND)
        
        analysis = pdf_file.analysis
        return Response({
            "pdf_id": pdf_id,
            "is_malicious": pdf_file.is_malicious,
            "confidence": pdf_file.prediction_confidence,
            "features": analysis.features,
            "explanation": analysis.explanation,
            "report_path": pdf_file.report_file.url if pdf_file.report_file else None
        })
    except PDFFile.DoesNotExist:
        return Response({"error": "PDF file not found"}, status=status.HTTP_404_NOT_FOUND)

# pmd_final_batch_1/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PDFFileViewSet, register_user, login_user, get_analysis_results

router = DefaultRouter()
router.register(r'pdfs', PDFFileViewSet, basename='pdf')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('analysis/<int:pdf_id>/', get_analysis_results, name='analysis'),
]