import pandas as pd
import joblib
from extract_pdf_features import extract_pdf_features  # Ensure this function is implemented correctly
from sklearn.preprocessing import StandardScaler

# ✅ Define the exact feature order used during training
EXPECTED_COLUMNS = [
    "header_length", "file_size_kb", "num_pages", "is_encrypted",
    "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
]

# 🔄 Load the trained scaler
SCALER_PATH = "scaler.pkl"

def preprocess_pdf(pdf_path):
    """Extract features, preprocess them, and return the scaled input for the model."""
    try:
        # 🔹 Step 1: Extract Features
        extracted_features = extract_pdf_features(pdf_path)
        extracted_features["file_name"] = pdf_path  # Add filename for reference

        # 🔹 Step 2: Convert to DataFrame
        df_features = pd.DataFrame([extracted_features])

        # ✅ Debugging: Print extracted feature names before processing
        print("🔍 Extracted feature names before scaling:", df_features.columns.tolist())

        # 🔹 Step 3: Ensure Correct Feature Order
        df_features = df_features.reindex(columns=EXPECTED_COLUMNS, fill_value=0)  # Fill missing features

        # 🔹 Step 4: Handle Missing Values
        df_features.fillna(0, inplace=True)  

        # 🔹 Step 5: Apply Scaling
        scaler = joblib.load(SCALER_PATH)  # Load trained scaler
        df_features_scaled = scaler.transform(df_features)

        print(f"✅ Successfully processed {pdf_path}")
        return df_features_scaled

    except Exception as e:
        print(f"❌ Error processing {pdf_path}: {e}")
        return None
