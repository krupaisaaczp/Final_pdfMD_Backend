import os
import subprocess
from django.conf import settings

# Define paths for ML scripts and model files
ML_SCRIPTS_DIR = os.path.join(settings.BASE_DIR, "pmd_final_Batch_1", "ml_scripts")
MODEL_DIR = os.path.join(settings.BASE_DIR, "pmd_final_Batch_1", "models")

def extract_features(pdf_path):
    """ Extract features from the PDF file """
    script_path = os.path.join(ML_SCRIPTS_DIR, "extract_pdf_features.py")
    result = subprocess.run(["python", script_path, pdf_path], capture_output=True, text=True)
    return result.stdout.strip()

def preprocess_pdf(pdf_path):
    """ Preprocess the PDF file before feature extraction """
    script_path = os.path.join(ML_SCRIPTS_DIR, "preprocess_pdf.py")
    result = subprocess.run(["python", script_path, pdf_path], capture_output=True, text=True)
    return result.stdout.strip()

def preprocess_features(feature_path):
    """ Preprocess extracted features before prediction """
    script_path = os.path.join(ML_SCRIPTS_DIR, "preprocess_features.py")
    result = subprocess.run(["python", script_path, feature_path], capture_output=True, text=True)
    return result.stdout.strip()

def predict_malware(features_path):
    """ Run the prediction script using best_model.pkl """
    script_path = os.path.join(ML_SCRIPTS_DIR, "predict.py")
    model_path = os.path.join(MODEL_DIR, "best_model.pkl")
    scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
    
    result = subprocess.run(["python", script_path, features_path, model_path, scaler_path], capture_output=True, text=True)
    return result.stdout.strip()

def generate_report(pdf_path):
    """ Generate a malware analysis report for the PDF """
    script_path = os.path.join(ML_SCRIPTS_DIR, "generate_report.py")
    report_path = os.path.join(settings.MEDIA_ROOT, "reports", os.path.basename(pdf_path) + ".pdf")
    
    subprocess.run(["python", script_path, pdf_path, report_path])
    return report_path

def explain_prediction(pdf_path):
    """ Explain the malware prediction using SHAP or LIME """
    script_path = os.path.join(ML_SCRIPTS_DIR, "explain_prediction.py")
    explanation_path = pdf_path + "_explanation.txt"

    subprocess.run(["python", script_path, pdf_path, explanation_path])
    return explanation_path
