import os
import json
import subprocess
import numpy as np
import pandas as pd
import joblib
from django.conf import settings

# Define paths for ML scripts and model files
ML_SCRIPTS_DIR = os.path.join(settings.BASE_DIR, "pmd_final_batch_1", "ml_scripts")
MODEL_DIR = os.path.join(settings.BASE_DIR, "pmd_final_batch_1", "models")

def extract_features(pdf_path):
    """Extract features from the PDF file"""
    try:
        # Import directly to avoid subprocess issues
        from .ml_scripts.extract_pdf_features import extract_pdf_features
        return extract_pdf_features(pdf_path)
    except ImportError:
        script_path = os.path.join(ML_SCRIPTS_DIR, "extract_pdf_features.py")
        result = subprocess.run(["python", script_path, pdf_path], capture_output=True, text=True)
        return json.loads(result.stdout.strip())

def preprocess_features(features):
    """Preprocess extracted features for prediction"""
    try:
        # Define expected features
        expected_features = [
            "header_length", "file_size_kb", "num_pages", "is_encrypted",
            "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
        ]
        
        # Create a DataFrame with the expected features
        df = pd.DataFrame([{k: features.get(k, 0) for k in expected_features}])
        
        # Load the scaler
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        scaler = joblib.load(scaler_path)
        
        # Scale the features
        scaled_features = scaler.transform(df)
        return scaled_features
    except Exception as e:
        raise Exception(f"Error preprocessing features: {str(e)}")

def predict_malware(features):
    """Make a prediction using the pre-trained model"""
    try:
        # Load the model
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        model = joblib.load(model_path)
        
        # Make prediction
        prediction = model.predict(features)[0]
        
        # Get probability
        try:
            probability = model.predict_proba(features)[0][1]  # Probability of malicious
        except:
            probability = 0.5  # Default if model doesn't support probabilities
            
        result = "Malicious" if prediction == 1 else "Benign"
        return {"prediction": result, "confidence": float(probability)}
    except Exception as e:
        raise Exception(f"Error making prediction: {str(e)}")

def generate_report(pdf_path, report_filename):
    """Generate a report for the PDF analysis"""
    try:
        from fpdf import FPDF
        import matplotlib.pyplot as plt
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(settings.MEDIA_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Get features and prediction
        features = extract_features(pdf_path)
        processed_features = preprocess_features(features)
        prediction_result = predict_malware(processed_features)
        
        # Create PDF report
        report_path = os.path.join(reports_dir, report_filename)
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "PDF Malware Detection Report", ln=True, align="C")
        pdf.ln(10)
        
        # File information
        pdf.set_font("Arial", "", 12)
        pdf.cell(200, 10, f"File: {os.path.basename(pdf_path)}", ln=True)
        pdf.cell(200, 10, f"Prediction: {prediction_result['prediction']}", ln=True)
        pdf.cell(200, 10, f"Confidence: {prediction_result['confidence']:.2f}", ln=True)
        pdf.ln(10)
        
        # Features
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, "Features Detected:", ln=True)
        pdf.set_font("Arial", "", 12)
        
        # Add important features
        for key, value in features.items():
            if key in ["pdf_version", "num_pages", "text_length", "num_images", "has_javascript"]:
                pdf.cell(200, 10, f"{key}: {value}", ln=True)
        
        pdf.output(report_path)
        return report_path
    except Exception as e:
        raise Exception(f"Error generating report: {str(e)}")

def explain_prediction(pdf_path, features):
    """Explain the prediction using feature importance"""
    try:
        # Load the model
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        model = joblib.load(model_path)
        
        # Get feature names
        feature_names = [
            "header_length", "file_size_kb", "num_pages", "is_encrypted",
            "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
        ]
        
        # Get feature importances if the model supports it
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            feature_importance = {feature_names[i]: float(importances[i]) for i in range(len(feature_names))}
            
            # Create explanation text
            explanation = "Feature Importance:\n\n"
            for feature, importance in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True):
                explanation += f"{feature}: {importance:.4f}\n"
            
            return explanation
        else:
            return "Model does not provide feature importance information."
    except Exception as e:
        return f"Error explaining prediction: {str(e)}"
