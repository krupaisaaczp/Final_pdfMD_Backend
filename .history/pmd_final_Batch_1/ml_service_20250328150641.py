import os
import subprocess
from django.conf import settings
from .models import PDFFile

def extract_features(pdf_path):
    """ Extract features from the PDF file """
    result = subprocess.run(["python", "extract_pdf_features.py", pdf_path], capture_output=True, text=True)
    return result.stdout.strip()

def predict_malware(features_path):
    """ Run the prediction script """
    result = subprocess.run(["python", "predict.py", features_path], capture_output=True, text=True)
    return result.stdout.strip()

def generate_report(pdf_path):
    """ Generate a report for the PDF """
    report_path = os.path.join(settings.MEDIA_ROOT, "reports", os.path.basename(pdf_path) + ".pdf")
    subprocess.run(["python", "generate_report.py", pdf_path, report_path])
    return report_path

def explain_prediction(pdf_path):
    """ Explain the model's prediction """
    explanation_path = pdf_path + "_explanation.txt"
    subprocess.run(["python", "explain_pdf.py", pdf_path, explanation_path])
    return explanation_path
