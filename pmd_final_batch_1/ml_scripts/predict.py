import joblib
import numpy as np
from preprocess_pdf import preprocess_pdf

# Load trained model
MODEL_PATH = "best_model.pkl"
model = joblib.load(MODEL_PATH)

def predict_pdf(pdf_path):
    """Analyze an uploaded PDF file and return the prediction result."""
    try:
        print(f"Processing file: {pdf_path}")

        # Step 1: Extract and preprocess features
        features = preprocess_pdf(pdf_path)

        if features is None:
            print(f"Feature extraction failed for {pdf_path}")
            return {"file": pdf_path, "prediction": "Error", "confidence": 0.0}

        # Step 2: Ensure features are in the correct format
        features = np.array(features).reshape(1, -1)

        # Step 3: Make prediction
        prediction = model.predict(features)[0]

        # Step 4: Get probability (if supported)
        try:
            probability = model.predict_proba(features)[0][1]  # Malicious probability
        except AttributeError:
            probability = 0.5

        # Step 5: Prepare response
        result = "Malicious" if prediction == 1 else "Benign"
        print(f"Prediction for {pdf_path}: {result} ({probability:.4f} confidence)")

        return {"file": pdf_path, "prediction": result, "confidence": probability}

    except Exception as e:
        print(f"Error predicting {pdf_path}: {e}")
        return {"file": pdf_path, "prediction": "Error", "confidence": 0.0}