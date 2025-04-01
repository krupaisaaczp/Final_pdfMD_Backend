import os
import uuid
import json
from pathlib import Path
from django.conf import settings
from django.core.files.storage import default_storage
from django.contrib.auth import authenticate
from django.http import FileResponse
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, renderer_classes
from rest_framework.renderers import JSONRenderer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.authtoken.models import Token
import logging

from .models import PDFFile, AnalysisResult
from .serializers import PDFFileSerializer, UserSerializer
from .ml_service import (
    preprocess_pdf, extract_features, preprocess_features,
    predict_malware, generate_report, explain_prediction
)

# Set up logging
logger = logging.getLogger(__name__)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

@api_view(['POST'])
@permission_classes([AllowAny])
@renderer_classes([JSONRenderer])  # Force JSON response
def register_user(request):
    logger.debug(f"Register request data: {request.data}")
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': serializer.data
        }, status=status.HTTP_201_CREATED)
    logger.debug(f"Register errors: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@renderer_classes([JSONRenderer])
def login_user(request):
    logger.debug(f"Login request data: {request.data}")
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user:
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        })
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([AllowAny])
@renderer_classes([JSONRenderer])
def token_auth(request):
    return login_user(request)  # Same logic as login_user

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

class PDFFileViewSet(viewsets.ModelViewSet):
    serializer_class = PDFFileSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    renderer_classes = [JSONRenderer]  # Force JSON response
    
    def get_queryset(self):
        return PDFFile.objects.filter(user=self.request.user)
    
    def create(self, request, *args, **kwargs):
        logger.debug(f"PDFFileViewSet request files: {request.FILES}")
        if 'file' not in request.FILES:
            return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES['file']
        if not file.name.lower().endswith('.pdf'):
            return Response({"error": "File must be a PDF"}, status=status.HTTP_400_BAD_REQUEST)
        if file.size > MAX_FILE_SIZE:
            return Response({"error": "File exceeds 10MB limit"}, status=status.HTTP_400_BAD_REQUEST)

        filename = f"{uuid.uuid4()}_{file.name}"
        file_path = default_storage.save(f"pdfs/{filename}", file)
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
                file=file_path,
                is_malicious=is_malicious,
                prediction_confidence=confidence,
                report_file=report_relative_path,
                user=request.user
            )
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
                "report_url": pdf_instance.report_file.url,
                "timestamp": pdf_instance.uploaded_at
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            if default_storage.exists(file_path):
                default_storage.delete(file_path)
            return Response({"error": f"Analysis failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def analyze_pdf(request):
    logger.debug(f"Analyze PDF request files: {request.FILES}")
    if 'pdf_file' not in request.FILES:
        return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

    pdf_files = request.FILES.getlist('pdf_file')
    if len(pdf_files) != 1:
        return Response({"error": "Exactly one PDF file must be uploaded"}, status=status.HTTP_400_BAD_REQUEST)

    file = pdf_files[0]
    if not file.name.lower().endswith('.pdf'):
        return Response({"error": "File must be a PDF"}, status=status.HTTP_400_BAD_REQUEST)
    if file.size > MAX_FILE_SIZE:
        return Response({"error": "File exceeds 10MB limit"}, status=status.HTTP_400_BAD_REQUEST)

    filename = f"{uuid.uuid4()}_{file.name}"
    file_path = default_storage.save(f"pdfs/{filename}", file)
    absolute_file_path = Path(settings.MEDIA_ROOT) / file_path

    try:
        raw_features = extract_features(str(absolute_file_path))
        processed_features = preprocess_features(raw_features)
        prediction_result = predict_malware(processed_features)
        is_malicious = prediction_result['prediction'].lower() == "malicious"
        confidence = prediction_result['confidence']

        suspicious_features = ['has_javascript', 'has_embedded_files', 'has_openaction', 'has_launch']
        has_suspicious = any(raw_features.get(k, 0) == 1 for k in suspicious_features)
        file_size_kb = raw_features.get('file_size_kb', 0)
        
        if is_malicious and not has_suspicious and confidence < 0.98 and file_size_kb < 1000:
            is_malicious = False

        report_filename = f"{uuid.uuid4()}_report.pdf"
        report_path = generate_report(str(absolute_file_path), report_filename)
        report_relative_path = os.path.relpath(report_path, settings.MEDIA_ROOT)

        explanation = explain_prediction(str(absolute_file_path), processed_features)

        pdf_instance = PDFFile.objects.create(
            file=file_path,
            is_malicious=is_malicious,
            prediction_confidence=confidence,
            report_file=report_relative_path,
            user=request.user
        )
        analysis = AnalysisResult.objects.create(
            pdf_file=pdf_instance,
            features=raw_features,
            explanation=explanation
        )

        formatted_features = [
            {"name": k, "value": v, "is_suspicious": k in suspicious_features and v == 1}
            for k, v in analysis.features.items()
        ]
        recommendations = ["This PDF appears to be safe, but always exercise caution."] if not is_malicious else [
            "Do not open this PDF as it may contain malware.",
            "Scan this file with an antivirus program before opening."
        ] + [f"This PDF contains {k.replace('has_', '')} which could be malicious." for k in suspicious_features if raw_features.get(k, 0) == 1]

        return Response({
            "file_id": pdf_instance.id,
            "file_name": filename,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "timestamp": pdf_instance.uploaded_at,
            "features": formatted_features,
            "explanation": explanation,
            "recommendations": recommendations,
            "report_url": pdf_instance.report_file.url
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        if default_storage.exists(file_path):
            default_storage.delete(file_path)
        return Response({"error": f"Analysis failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def get_analysis_results(request, pdf_id):
    try:
        pdf_file = PDFFile.objects.get(id=pdf_id, user=request.user)
        if not hasattr(pdf_file, 'analysis'):
            return Response({"error": "No analysis available for this file"}, status=status.HTTP_404_NOT_FOUND)
        
        analysis = pdf_file.analysis
        suspicious_features = ['has_javascript', 'has_embedded_files', 'has_openaction', 'has_launch']
        
        formatted_features = [
            {"name": k, "value": v, "is_suspicious": k in suspicious_features and v == 1}
            for k, v in analysis.features.items()
        ]
        
        recommendations = ["This PDF appears to be safe, but always exercise caution."] if not pdf_file.is_malicious else [
            "Do not open this PDF as it may contain malware.",
            "Scan this file with an antivirus program before opening."
        ] + [f"This PDF contains {k.replace('has_', '')} which could be malicious." for k in suspicious_features if analysis.features.get(k, 0) == 1]

        return Response({
            "file_id": pdf_id,
            "file_name": os.path.basename(pdf_file.file.name),
            "is_malicious": pdf_file.is_malicious,
            "confidence": pdf_file.prediction_confidence,
            "timestamp": pdf_file.uploaded_at,
            "features": formatted_features,
            "explanation": analysis.explanation,
            "recommendations": recommendations,
            "report_url": pdf_file.report_file.url
        })
    except PDFFile.DoesNotExist:
        return Response({"error": "PDF file not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def analysis_history(request):
    pdfs = PDFFile.objects.filter(user=request.user).order_by('-uploaded_at')
    history = [{
        "id": pdf.id,
        "file_name": os.path.basename(pdf.file.name),
        "uploaded_at": pdf.uploaded_at,
        "is_malicious": pdf.is_malicious,
        "confidence": pdf.prediction_confidence,
        "report_url": pdf.report_file.url if pdf.report_file else None
    } for pdf in pdfs]
    return Response(history)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_report(request, pdf_id):  # No JSONRenderer here since it’s a file response
    try:
        pdf_file = PDFFile.objects.get(id=pdf_id, user=request.user)
        report_path = os.path.join(settings.MEDIA_ROOT, pdf_file.report_file.name)
        if not os.path.exists(report_path):
            return Response({"error": "Report file not found"}, status=status.HTTP_404_NOT_FOUND)
        
        response = FileResponse(open(report_path, 'rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{pdf_id}.pdf"'
        return response
    except PDFFile.DoesNotExist:
        return Response({"error": "PDF file not found"}, status=status.HTTP_404_NOT_FOUND)