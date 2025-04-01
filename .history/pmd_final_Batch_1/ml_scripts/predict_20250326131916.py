import joblib
from AIML_BATCH_1_Project.backend.preprocess_pdf import preprocess_pdf  # ✅ Fixed Import

# ✅ Load trained model
MODEL_PATH = "best_model.pkl"
model = joblib.load(MODEL_PATH)

def predict_pdf(pdf_path):
    """Load PDF, extract features, preprocess, and make a prediction."""
    try:
        # ✅ Preprocess the PDF file
        features = preprocess_pdf(pdf_path)

        if features is None:
            return None  # Skip prediction if feature extraction fails

        # 🔹 Ensure features match model expectations
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1]  # Probability of being malicious

        result = "Malicious" if prediction == 1 else "Benign"
        print(f"✅ Prediction for {pdf_path}: {result} ({probability:.4f} confidence)")
        return {"file": pdf_path, "prediction": result, "confidence": probability}

    except Exception as e:
        print(f"❌ Error predicting {pdf_path}: {e}")
        return None

# Example Usage
pdf_file = "sample.pdf"
prediction_result = predict_pdf(pdf_file)
