import os
import json
import subprocess
import numpy as np
import pandas as pd
import joblib
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

ML_SCRIPTS_DIR = os.path.join(settings.BASE_DIR, "pmd_final_batch_1", "ml_scripts")
MODEL_DIR = os.path.join(settings.BASE_DIR, "pmd_final_batch_1", "models")

def extract_features(pdf_path):
    script_path = os.path.join(ML_SCRIPTS_DIR, "extract_pdf_features.py")
    try:
        logger.info(f"Extracting features from {pdf_path}")
        result = subprocess.run(
            ["python", script_path, pdf_path],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        if not output:
            raise ValueError("Feature extraction script returned empty output")
        features = json.loads(output)
        if isinstance(features, dict) and "error" in features:
            raise Exception(features["error"])
        logger.debug(f"Features extracted: {features}")
        return features
    except subprocess.CalledProcessError as e:
        logger.error(f"Feature extraction failed: {e.stderr}")
        raise Exception(f"Feature extraction failed: {e.stderr}")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON output: {result.stdout if 'result' in locals() else 'No output'}")
        raise Exception(f"Invalid JSON output from feature extraction")
    except Exception as e:
        logger.error(f"Error extracting features: {str(e)}")
        raise Exception(f"Error extracting features: {str(e)}")

def preprocess_pdf(pdf_path):
    try:
        features = extract_features(pdf_path)
        return preprocess_features(features)
    except Exception as e:
        logger.error(f"Error preprocessing PDF: {str(e)}")
        raise Exception(f"Error preprocessing PDF: {str(e)}")

def preprocess_features(features):
    try:
        expected_features = [
            "header_length", "file_size_kb", "num_pages", "is_encrypted",
            "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
        ]
        df = pd.DataFrame([{k: features.get(k, 0) for k in expected_features}])
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        if not os.path.exists(scaler_path):
            logger.error(f"Scaler file not found at {scaler_path}")
            raise FileNotFoundError(f"Scaler file not found at {scaler_path}")
        scaler = joblib.load(scaler_path)
        scaled_features = scaler.transform(df)
        logger.debug(f"Raw Features: {dict(zip(expected_features, df.iloc[0]))}")
        logger.debug(f"Scaled Features: {dict(zip(expected_features, scaled_features[0]))}")
        return scaled_features
    except Exception as e:
        logger.error(f"Error in preprocess_features: {str(e)}")
        raise Exception(f"Error preprocessing features: {str(e)}")

def predict_malware(features):
    try:
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        if not os.path.exists(model_path):
            logger.error(f"Model file not found at {model_path}")
            raise FileNotFoundError(f"Model file not found at {model_path}")
        model = joblib.load(model_path)
        prediction = model.predict(features)[0]
        probability = getattr(model, 'predict_proba', lambda x: [0.5, 0.5])(features)[0][1]
        result = "Malicious" if probability > 0.5 else "Benign"
        logger.info(f"Prediction: {result}, Confidence: {probability}")
        return {"prediction": result, "confidence": float(probability)}
    except Exception as e:
        logger.error(f"Error in predict_malware: {str(e)}")
        raise Exception(f"Error making prediction: {str(e)}")

def generate_report(pdf_path, report_filename):
    try:
        from fpdf import FPDF
        reports_dir = os.path.join(settings.MEDIA_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        features = extract_features(pdf_path)
        processed_features = preprocess_features(features)
        prediction_result = predict_malware(processed_features)
        report_path = os.path.join(reports_dir, report_filename)
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "PDF Malware Detection Report", ln=True, align="C")
        pdf.ln(10)
        pdf.set_font("Arial", "", 12)
        pdf.cell(200, 10, f"File: {os.path.basename(pdf_path)}", ln=True)
        pdf.cell(200, 10, f"File Size: {features.get('@file_size_kb', 'N/A')} KB", ln=True)
        pdf.cell(200, 10, f"File Hash (SHA-256): {features.get('file_hash', 'N/A')}", ln=True)
        pdf.cell(200, 10, f"PDF Version: {features.get('pdf_version', 'N/A')}", ln=True)
        pdf.cell(200, 10, f"Author: {features.get('author', 'Not specified')}", ln=True)
        pdf.cell(200, 10, f"Creation Date: {features.get('creation_date', 'Not specified')}", ln=True)
        pdf.cell(200, 10, f"Prediction: {prediction_result['prediction']}", ln=True)
        pdf.cell(200, 10, f"Confidence: {prediction_result['confidence']:.2f}", ln=True)
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, "Features Detected:", ln=True)
        pdf.set_font("Arial", "", 12)
        for key, value in features.items():
            if key in ["header_length", "file_size_kb", "num_pages", "is_encrypted", "has_javascript", "has_embedded_files", "has_openaction", "has_launch"]:
                pdf.cell(200, 10, f"{key}: {value}", ln=True)
        pdf.output(report_path)
        return report_path
    except Exception as e:
        logger.error(f"Error in generate_report: {str(e)}")
        raise Exception(f"Error generating report: {str(e)}")

def explain_prediction(pdf_path, features):
    try:
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        model = joblib.load(model_path)
        feature_names = [
            "header_length", "file_size_kb", "num_pages", "is_encrypted",
            "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
        ]
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            feature_importance = {feature_names[i]: float(importances[i]) for i in range(len(feature_names))}
            explanation = "Feature Importance:\n\n"
            for feature, importance in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True):
                explanation += f"{feature}: {importance:.4f}\n"
            return explanation
        else:
            return "Model does not provide feature importance information."
    except Exception as e:
        logger.error(f"Error in explain_prediction: {str(e)}")
        raise Exception(f"Error explaining prediction: {str(e)}")