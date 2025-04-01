import shap
import joblib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from AIML_BATCH_1_Project.backend.preprocess_pdf import preprocess_pdf

# Load trained model and scaler
MODEL_PATH = "best_model.pkl"
SCALER_PATH = "scaler.pkl"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Expected feature order (MUST match training!)
FEATURE_COLUMNS = [
    "header_length", "file_size_kb", "num_pages", "is_encrypted",
    "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
]

# Function to explain predictions
def explain_pdf(pdf_path):
    try:
        # Step 1: Extract and preprocess features
        features_scaled = preprocess_pdf(pdf_path)
        if features_scaled is None:
            return
        
        # Step 2: Convert to DataFrame
        df_features = pd.DataFrame(features_scaled, columns=FEATURE_COLUMNS)
        
        # Step 3: Generate SHAP values
        explainer = shap.Explainer(model)
        shap_values = explainer(df_features)

        # 🔹 Save Force Plot (Single PDF)
        force_plot = shap.plots.force(shap_values[0])
        shap.save_html(f"shap_explanation_{pdf_path}.html", force_plot)
        print(f"✅ SHAP Force Plot saved as shap_explanation_{pdf_path}.html")

        # 🔹 Save Summary Plot (Feature Importance)
        plt.figure(figsize=(10, 6))
        shap.summary_plot(shap_values, df_features, show=False)
        plt.savefig(f"shap_summary_{pdf_path}.png", bbox_inches="tight")
        print(f"✅ SHAP Summary Plot saved as shap_summary_{pdf_path}.png")

    except Exception as e:
        print(f"❌ Error explaining {pdf_path}: {e}")

# Example Usage
pdf_file = "sample.pdf"
explain_pdf(pdf_file)
