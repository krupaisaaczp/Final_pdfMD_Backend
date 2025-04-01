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
        return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    
    if user:
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'user': UserSerializer(user).data})
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

class PDFFileViewSet(viewsets.ModelViewSet):
    serializer_class = PDFFileSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return PDFFile.objects.filter(user=self.request.user)
    
    def create(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        if not uploaded_file.name.lower().endswith('.pdf'):
            return Response({"error": "File must be a PDF"}, status=status.HTTP_400_BAD_REQUEST)

        filename = f"{uuid.uuid4()}_{uploaded_file.name}"
        file_path = default_storage.save(f"pdfs/{filename}", uploaded_file)
        absolute_file_path = Path(settings.MEDIA_ROOT) / file_path

        try:
            raw_features = extract_features(str(absolute_file_path))
            processed_features = preprocess_features(raw_features)
            prediction_result = predict_malware(processed_features)
            is_malicious = prediction_result['prediction'].lower() == "malicious"
            confidence = prediction_result['confidence']

            report_filename = f"{uuid.uuid4()}_report.pdf"
            report_path = generate_report(str(absolute_file_path), report_filename)
            report_relative_path = os.path.relpath(report_path, settings.MEDIA_ROOT)

            explanation = explain_prediction(str(absolute_file_path), processed_features)

            pdf_instance = PDFFile.objects.create(
                file=file_path, is_malicious=is_malicious,
                prediction_confidence=confidence, report_file=report_relative_path,
                user=request.user
            )
            AnalysisResult.objects.create(pdf_file=pdf_instance, features=raw_features, explanation=explanation)

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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def analyze_pdf(request):
    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

    pdf_viewset = PDFFileViewSet.as_view({'post': 'create'})
    return pdf_viewset(request)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_analysis_results(request, pdf_id):
    try:
        pdf_file = PDFFile.objects.get(id=pdf_id, user=request.user)
        if not hasattr(pdf_file, 'analysis'):
            return Response({"error": "No analysis available for this file"}, status=status.HTTP_404_NOT_FOUND)
        
        analysis = pdf_file.analysis
        formatted_features = [
            {"name": key, "value": value, "is_suspicious": value == 1 and key in ['has_javascript', 'has_embedded_files', 'has_openaction', 'has_launch']}
            for key, value in analysis.features.items()
        ]
        
        recommendations = [
            "Do not open this PDF as it may contain malware." if pdf_file.is_malicious else "This PDF appears to be safe, but always exercise caution.",
            "Scan this file with an antivirus program before opening."
        ]
        if pdf_file.is_malicious and analysis.features.get('has_javascript', 0) == 1:
            recommendations.append("This PDF contains JavaScript which could be malicious.")
        if pdf_file.is_malicious and analysis.features.get('has_embedded_files', 0) == 1:
            recommendations.append("This PDF has embedded files which could contain malware.")
        
        return Response({
            "file_id": pdf_id,
            "file_name": pdf_file.file.name.split('/')[-1],
            "is_malicious": pdf_file.is_malicious,
            "confidence": pdf_file.prediction_confidence,
            "timestamp": pdf_file.uploaded_at,
            "features": formatted_features,
            "explanation": analysis.explanation,
            "recommendations": recommendations,
            "report_url": pdf_file.report_file.url if pdf_file.report_file else None
        })
    except PDFFile.DoesNotExist:
        return Response({"error": "PDF file not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def analysis_history(request):
    pdfs = PDFFile.objects.filter(user=request.user).order_by('-uploaded_at')
    history = [{
        "id": pdf.id, "file_name": pdf.file.name.split('/')[-1],
        "uploaded_at": pdf.uploaded_at, "is_malicious": pdf.is_malicious,
        "confidence": pdf.prediction_confidence
    } for pdf in pdfs]
    return Response(history)
