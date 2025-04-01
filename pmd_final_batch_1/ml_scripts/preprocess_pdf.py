import pandas as pd
import joblib

# Define the exact feature order used during training
EXPECTED_COLUMNS = [
    "header_length", "file_size_kb", "num_pages", "is_encrypted",
    "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
]

# Load the trained scaler
SCALER_PATH = "scaler.pkl"

def preprocess_pdf(pdf_path):
    """Extract features, preprocess them, and return the scaled input for the model."""
    try:
        # Step 1: Extract Features
        from extract_pdf_features import extract_pdf_features
        extracted_features = extract_pdf_features(pdf_path)
        if "error" in extracted_features:
            raise Exception(extracted_features["error"])

        # Step 2: Convert to DataFrame
        df_features = pd.DataFrame([extracted_features])

        # Step 3: Ensure Correct Feature Order
        df_features = df_features.reindex(columns=EXPECTED_COLUMNS, fill_value=0)

        # Step 4: Handle Missing Values
        df_features.fillna(0, inplace=True)

        # Step 5: Apply Scaling
        scaler = joblib.load(SCALER_PATH)
        df_features_scaled = scaler.transform(df_features)

        print(f"Scaled features for {pdf_path}: {df_features_scaled}")  # Debug log
        return df_features_scaled

    except Exception as e:
        print(f"Error processing {pdf_path}: {e}")
        return None