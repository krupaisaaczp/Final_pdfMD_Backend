from fpdf import FPDF
import os
import joblib
import shap
import matplotlib.pyplot as plt
import pandas as pd
from AIML_BATCH_1_Project.backend.preprocess_pdf import preprocess_pdf
from predict_pdf import predict_pdf

# Paths
MODEL_PATH = "best_model.pkl"
SCALER_PATH = "scaler.pkl"
REPORTS_DIR = "reports"

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)

# Load Model
model = joblib.load(MODEL_PATH)

# Expected Features (Must match model training)
FEATURE_COLUMNS = [
    "header_length", "file_size_kb", "num_pages", "is_encrypted",
    "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
]

def generate_shap_plot(features_scaled, pdf_name):
    """Generate SHAP Summary Plot"""
    df_features = pd.DataFrame(features_scaled, columns=FEATURE_COLUMNS)
    explainer = shap.Explainer(model)
    shap_values = explainer(df_features)

    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_values, df_features, show=False)
    shap_plot_path = os.path.join(REPORTS_DIR, f"shap_summary_{pdf_name}.png")
    plt.savefig(shap_plot_path, bbox_inches="tight")
    return shap_plot_path

def generate_pdf_report(pdf_path):
    """Generate PDF Report for Malware Detection"""
    try:
        # Step 1: Preprocess & Predict
        features_scaled = preprocess_pdf(pdf_path)
        if features_scaled is None:
            print(f"❌ Failed to process {pdf_path}")
            return
        
        prediction = predict_pdf(pdf_path)
        if not prediction:
            print(f"❌ Failed to classify {pdf_path}")
            return

        # Extract results
        classification = prediction["prediction"]
        confidence = prediction["confidence"]

        # Step 2: Generate SHAP Explanation
        shap_plot_path = generate_shap_plot(features_scaled, os.path.basename(pdf_path))

        # Step 3: Create PDF Report
        report_path = os.path.join(REPORTS_DIR, f"report_{os.path.basename(pdf_path)}.pdf")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "PDF Malware Detection Report", ln=True, align="C")
        pdf.ln(10)

        # File Details
        pdf.set_font("Arial", "", 12)
        pdf.cell(200, 10, f"File: {pdf_path}", ln=True)
        pdf.cell(200, 10, f"Prediction: {classification}", ln=True)
        pdf.cell(200, 10, f"Confidence: {confidence:.2f}", ln=True)
        pdf.ln(10)

        # Add SHAP Explanation
        if os.path.exists(shap_plot_path):
            pdf.cell(200, 10, "Feature Importance (SHAP):", ln=True)
            pdf.image(shap_plot_path, x=10, w=180)

        # Save Report
        pdf.output(report_path)
        print(f"✅ Report generated: {report_path}")

    except Exception as e:
        print(f"❌ Error generating report for {pdf_path}: {e}")

# Example Usage
pdf_file = "sample.pdf"
generate_pdf_report(pdf_file)
