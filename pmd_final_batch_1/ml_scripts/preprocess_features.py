import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler

# 🔹 Load training dataset
df_train = pd.read_csv(r"D:\Final_Batch_1\file_dataset.csv")

# ✅ Define feature columns (MUST match model expectation, `pdf_version` REMOVED)
FEATURE_COLUMNS = [
    "header_length", "file_size_kb", "num_pages", "is_encrypted",
    "has_javascript", "has_embedded_files", "has_openaction", "has_launch"
]

# 🔍 Ensure all required features exist in dataset
missing_features = [col for col in FEATURE_COLUMNS if col not in df_train.columns]
if missing_features:
    raise ValueError(f"❌ Missing columns in dataset: {missing_features}")

# 🛠️ Extract and clean features
X_train = df_train[FEATURE_COLUMNS].copy()
X_train.replace(["-1.-1", "-1"], pd.NA, inplace=True)  # Convert invalid values to NaN
X_train = X_train.apply(pd.to_numeric, errors="coerce")  # Convert all to numeric
X_train.fillna(X_train.mean(), inplace=True)  # Fill NaNs with mean values

# 🔄 Retrain StandardScaler **without `pdf_version`**
scaler = StandardScaler()
scaler.fit(X_train)

# 💾 Save the new scaler
joblib.dump(scaler, "scaler.pkl")

print("✅ New Scaler saved as `scaler.pkl` with features:", FEATURE_COLUMNS)
