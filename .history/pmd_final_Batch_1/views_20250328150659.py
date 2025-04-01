from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.files.storage import default_storage
from .models import PDFFile
from .serializers import PDFFileSerializer
from .ml_service import extract_features, predict_malware, generate_report, explain_prediction

class PDFFileViewSet(viewsets.ModelViewSet):
    queryset = PDFFile.objects.all()
    serializer_class = PDFFileSerializer
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        """ Handle PDF Upload and process it through ML pipeline """
        file = request.FILES['file']
        file_path = default_storage.save(f"pdfs/{file.name}", file)
        
        # Step 1: Extract Features
        features_path = extract_features(file_path)
        
        # Step 2: Predict Malware
        prediction = predict_malware(features_path)
        is_malicious = prediction.lower() == "malicious"
        
        # Step 3: Generate Report
        report_path = generate_report(file_path)

        # Step 4: Explain the Prediction
        explanation_path = explain_prediction(file_path)

        # Save to DB
        pdf_instance = PDFFile.objects.create(file=file, is_malicious=is_malicious)
        pdf_instance.save()

        return Response({
            "message": "File uploaded successfully",
            "file": file.name,
            "is_malicious": is_malicious,
            "report_path": report_path,
            "explanation_path": explanation_path
        }, status=status.HTTP_201_CREATED)
