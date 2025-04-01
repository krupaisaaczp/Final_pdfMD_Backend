def preprocess_features(features):
    try:
        expected_features = [
            "header_length", "file_size_kb", "num_pages", "is_encrypted",
            "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
        ]
        df = pd.DataFrame([{k: features.get(k, 0) for k in expected_features}])
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        scaler = joblib.load(scaler_path)
        scaled_features = scaler.transform(df)
        print("Raw Features:", dict(zip(expected_features, df.iloc[0])))
        print("Scaled Features:", dict(zip(expected_features, scaled_features[0])))
        return scaled_features
    except Exception as e:
        raise Exception(f"Error preprocessing features: {str(e)}")