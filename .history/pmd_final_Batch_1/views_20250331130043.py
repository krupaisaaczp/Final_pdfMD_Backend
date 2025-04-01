# Updated views.py
from django.core.files.storage import default_storage
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authtoken.models import Token
import os
import uuid
import json
from pathlib import Path

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

# Adding token auth endpoint to match frontend
@api_view(['POST'])
@permission_classes([AllowAny])
def token_auth(request):
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

# Add user profile endpoint
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
            analysis_result = AnalysisResult.objects.create(
                pdf_file=pdf_instance,
                features=raw_features,
                explanation=explanation
            )

            # Format features for frontend
            formatted_features = []
            for key, value in raw_features.items():
                # Determine if feature is suspicious based on some criteria
                is_suspicious = False
                if key == 'has_javascript' and value == 1:
                    is_suspicious = True
                elif key == 'has_embedded_files' and value == 1:
                    is_suspicious = True
                elif key == 'has_openaction' and value == 1:
                    is_suspicious = True
                elif key == 'has_launch' and value == 1:
                    is_suspicious = True
                elif key == 'is_encrypted' and value == 1:
                    is_suspicious = True
                
                formatted_features.append({
                    'name': key,
                    'value': value,
                    'is_suspicious': is_suspicious
                })
            
            # Create recommendations based on analysis
            recommendations = []
            if is_malicious:
                recommendations.append("Do not open this PDF as it may contain malware.")
                recommendations.append("Consider submitting this file to a security vendor for further analysis.")
                if raw_features.get('has_javascript', 0) == 1:
                    recommendations.append("This PDF contains JavaScript which can be used for exploitation.")
            else:
                recommendations.append("This PDF appears to be safe but always practice caution.")
            
            return Response({
                "message": "File uploaded and analyzed successfully",
                "file_id": pdf_instance.id,
                "file_name": filename,
                "is_malicious": is_malicious,
                "confidence": confidence,
                "report_path": report_relative_path,
                "timestamp": pdf_instance.uploaded_at,
                "features": formatted_features,
                "recommendations": recommendations
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
        
        # Format features for frontend
        formatted_features = []
        for key, value in analysis.features.items():
            # Determine if feature is suspicious
            is_suspicious = False
            if key == 'has_javascript' and value == 1:
                is_suspicious = True
            elif key == 'has_embedded_files' and value == 1:
                is_suspicious = True
            elif key == 'has_openaction' and value == 1:
                is_suspicious = True
            elif key == 'has_launch' and value == 1:
                is_suspicious = True
            elif key == 'is_encrypted' and value == 1:
                is_suspicious = True
            
            formatted_features.append({
                'name': key,
                'value': value,
                'is_suspicious': is_suspicious
            })
        
        # Create recommendations based on analysis
        recommendations = []
        if pdf_file.is_malicious:
            recommendations.append("Do not open this PDF as it may contain malware.")
            recommendations.append("Consider submitting this file to a security vendor for further analysis.")
            if analysis.features.get('has_javascript', 0) == 1:
                recommendations.append("This PDF contains JavaScript which can be used for exploitation.")
        else:
            recommendations.append("This PDF appears to be safe but always practice caution.")
        
        return Response({
            "pdf_id": pdf_id,
            "file_name": os.path.basename(pdf_file.file.name),
            "is_malicious": pdf_file.is_malicious,
            "confidence": pdf_file.prediction_confidence,
            "features": formatted_features,
            "explanation": analysis.explanation,
            "report_path": pdf_file.report_file.url if pdf_file.report_file else None,
            "timestamp": pdf_file.uploaded_at,
            "recommendations": recommendations
        })
    except PDFFile.DoesNotExist:
        return Response({"error": "PDF file not found"}, status=status.HTTP_404_NOT_FOUND)

# Add endpoint for PDF analysis from frontend
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def analyze_pdf(request):
    if 'pdf_file' not in request.FILES:
        return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)
    
    file = request.FILES['pdf_file']
    if not file.name.lower().endswith('.pdf'):
        return Response({"error": "File must be a PDF"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Use the existing view logic
    viewset = PDFFileViewSet()
    viewset.request = request
    request.FILES['file'] = file  # Rename to match expected field
    return viewset.create(request)

# Add endpoint for getting analysis history
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def analysis_history(request):
    pdfs = PDFFile.objects.filter(user=request.user).order_by('-uploaded_at')
    serializer = PDFFileSerializer(pdfs, many=True)
    return Response(serializer.data)