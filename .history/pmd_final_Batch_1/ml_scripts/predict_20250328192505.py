import joblib
import numpy as np
from AIML_BATCH_1_Project.backend.preprocess_pdf import preprocess_pdf  # ✅ Fixed Import

# ✅ Load trained model
MODEL_PATH = "best_model.pkl"
model = joblib.load(MODEL_PATH)

def predict_pdf(pdf_path):
    """Analyze an uploaded PDF file and return the prediction result."""
    try:
        print(f"🔍 Processing file: {pdf_path}")  # Debugging log

        # ✅ Step 1: Extract features
        features = preprocess_pdf(pdf_path)

        if features is None:
            print(f"⚠️ Feature extraction failed for {pdf_path}")
            return {"file": pdf_path, "prediction": "Error", "confidence": 0.0}

        # 🔹 Ensure features are in the correct format
        features = np.array(features).reshape(1, -1)  # ✅ Ensure 2D array

        # ✅ Step 2: Make prediction
        prediction = model.predict(features)[0]

        # ✅ Step 3: Get probability (if supported)
        try:
            probability = model.predict_proba(features)[0][1]  # Malicious probability
        except AttributeError:
            probability = 0.5  # Default probability if model doesn't support predict_proba

        # ✅ Step 4: Prepare response
        result = "Malicious" if prediction == 1 else "Benign"
        print(f"✅ Prediction for {pdf_path}: {result} ({probability:.4f} confidence)")

        return {"file": pdf_path, "prediction": result, "confidence": probability}

    except Exception as e:
        print(f"❌ Error predicting {pdf_path}: {e}")
        return {"file": pdf_path, "prediction": "Error", "confidence": 0.0}
