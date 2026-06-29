"""
ASTRA Static ML Model Training Pipeline
Trains a RandomForestClassifier on TUANDROMD permissions and API features.
"""

import json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
import shap

def main():
    # 1. Resolve CSV path and load data
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "TUANDROMD.csv"
    
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df.dropna(inplace=True)
    print(f"Dataset shape after dropping nulls: {df.shape}")
    print("\nClass distribution in raw data:")
    print(df["Label"].value_counts())
    
    # 2. Preprocess: Encode Label column (malware=1, goodware=0)
    df["Label"] = df["Label"].map({"malware": 1, "goodware": 0})
    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = list(X.columns)
    
    # 3. Print class distribution after encoding
    print("\nClass distribution after encoding:")
    print(y.value_counts())
    
    # Save feature names list to static_feature_names.json
    feature_names_path = base_dir / "static_feature_names.json"
    with open(feature_names_path, "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"Saved feature names list to {feature_names_path}")
    
    # 4. Train/Test Split (80% train, 20% test, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    
    # 5. Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 6. Train RandomForestClassifier
    print("\nTraining RandomForestClassifier (static model)...")
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
        min_samples_leaf=2
    )
    model.fit(X_train_scaled, y_train)
    print("Training completed.")
    
    # 7. Evaluate and print all metrics
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n=== Model Evaluation Metrics ===")
    print(f"Overall Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
    
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, target_names=["goodware", "malware"], digits=4)
    print(report)
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, pos_label=1, average="binary")
    print(f"\nMalware Class Metrics:")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    
    # 8. Save artifacts
    model_path = base_dir / "static_model.joblib"
    scaler_path = base_dir / "static_scaler.joblib"
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"Saved static model artifact to {model_path}")
    print(f"Saved static scaler artifact to {scaler_path}")
    
    # 9. SHAP Explainability meta
    print("\nComputing SHAP explainability meta on 100 samples...")
    explainer = shap.TreeExplainer(model)
    # Fit explainability values on X_test_scaled[:100]
    _ = explainer.shap_values(X_test_scaled[:100])
    
    expected_value = explainer.expected_value
    if hasattr(expected_value, "tolist"):
        expected_value_list = expected_value.tolist()
    elif isinstance(expected_value, (list, tuple)):
        expected_value_list = list(expected_value)
    else:
        expected_value_list = [float(expected_value)]
        
    shap_meta = {
        "expected_value": expected_value_list,
        "feature_names": feature_names,
        "class_names": {
            "0": "Goodware",
            "1": "Malware"
        }
    }
    
    shap_meta_path = base_dir / "static_shap_meta.json"
    with open(shap_meta_path, "w") as f:
        json.dump(shap_meta, f, indent=2)
    print(f"Saved static SHAP explainability metadata to {shap_meta_path}")
    
    # 10. Print final summary
    print("\n=== Final Static Training Summary ===")
    print(f"Accuracy Percentage: {acc * 100:.2f}%")
    print(f"Model Saved Path: {model_path}")
    print(f"Scaler Saved Path: {scaler_path}")
    print(f"Feature Count: {len(feature_names)}")

if __name__ == "__main__":
    main()
