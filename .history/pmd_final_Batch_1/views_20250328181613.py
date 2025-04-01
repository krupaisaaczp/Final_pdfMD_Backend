from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.files.storage import default_storage
from django.conf import settings
import os

from .models import PDFFile
from .serializers import PDFFileSerializer
from .ml_service import (
    preprocess_pdf, extract_features, preprocess_features,
    predict_malware, generate_report, explain_prediction
)

class PDFFileViewSet(viewsets.ModelViewSet):
    queryset = PDFFile.objects.all()
    serializer_class = PDFFileSerializer
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        """ Handle PDF upload and run the malware detection pipeline """
        if 'file' not in request.FILES:
            return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES['file']
        file_path = default_storage.save(f"pdfs/{file.name}", file)
        absolute_file_path = os.path.join(settings.MEDIA_ROOT, file_path)

        try:
            # Step 1: Preprocess PDF
            preprocess_pdf(absolute_file_path)

            # Step 2: Extract Features
            features_path = extract_features(absolute_file_path)

            # Step 3: Preprocess Features
            processed_features_path = preprocess_features(features_path)

            # Step 4: Predict Malware
            prediction = predict_malware(processed_features_path)
            is_malicious = prediction.lower() == "malicious"

            # Step 5: Generate Report
            report_path = generate_report(absolute_file_path)

            # Step 6: Explain the Prediction
            explanation_path = explain_prediction(absolute_file_path)

            # Step 7: Save to Database
            pdf_instance = PDFFile.objects.create(file=file, is_malicious=is_malicious)
            pdf_instance.save()

            return Response({
                "message": "File uploaded and analyzed successfully",
                "file": file.name,
                "is_malicious": is_malicious,
                "prediction": prediction,
                "report_path": report_path,
                "explanation_path": explanation_path
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
