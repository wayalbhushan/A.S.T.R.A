"""
ASTRA ML Model Training Pipeline
Trains a RandomForestClassifier on CICMalDroid binder/syscall frequencies.
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import shap

def load_data(csv_path: Path) -> pd.DataFrame:
    """Loads dataset from CSV and drops any rows containing null values."""
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"Loaded dataset of shape: {df.shape}")
    
    # Drop rows where any value is null
    df.dropna(inplace=True)
    print(f"Dataset shape after dropping nulls: {df.shape}")
    return df


def preprocess_and_split(df: pd.DataFrame):
    """Separates features and targets, and performs a stratified 80/20 train/test split."""
    # Features (X) are all columns except 'Class'
    # Target (y) is the 'Class' column
    X = df.drop(columns=["Class"])
    y = df["Class"]
    
    feature_names = list(X.columns)
    
    # Print class distribution before training
    print("\nClass distribution before split:")
    print(y.value_counts().sort_index())
    
    # Stratified split: 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    
    return X_train, X_test, y_train, y_test, feature_names


def scale_features(X_train: pd.DataFrame, X_test: pd.DataFrame):
    """Fits a StandardScaler on X_train only and transforms both partitions."""
    scaler = StandardScaler()
    
    # Fit and transform
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    return X_train_scaled, X_test_scaled, scaler


def train_model(X_train: np.ndarray, y_train: pd.Series) -> RandomForestClassifier:
    """Trains a Random Forest multiclass classifier on scaled data."""
    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
        max_depth=None,
        min_samples_leaf=2
    )
    model.fit(X_train, y_train)
    print("Training completed.")
    return model


def evaluate_model(model: RandomForestClassifier, X_test: np.ndarray, y_test: pd.Series):
    """Evaluates the model on test set and prints evaluation metrics."""
    y_pred = model.predict(X_test)
    
    # Metrics
    overall_acc = accuracy_score(y_test, y_pred)
    class_report = classification_report(y_test, y_pred, digits=4)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    print("\n=== Model Evaluation Metrics ===")
    print(f"Overall Accuracy: {overall_acc:.4f} ({overall_acc * 100:.2f}%)")
    
    print("\nClassification Report:")
    print(class_report)
    
    print("Confusion Matrix:")
    print(conf_matrix)
    
    print("\nPer-Class Accuracy:")
    per_class_acc = conf_matrix.diagonal() / conf_matrix.sum(axis=1)
    for cls, acc in zip(model.classes_, per_class_acc):
        print(f"Class {cls} Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
        
    return overall_acc


def generate_shap_meta(
    model: RandomForestClassifier, 
    X_test_scaled: np.ndarray, 
    feature_names: list
) -> dict:
    """Computes SHAP expected values and configurations for explanation metadata."""
    print("\nComputing SHAP explainability configurations...")
    explainer = shap.TreeExplainer(model)
    
    # Run SHAP value computations on first 100 test samples
    _ = explainer.shap_values(X_test_scaled[:100])
    
    # Parse expected values to list format dynamically
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
            "1": "Adware",
            "2": "Banking Malware",
            "3": "SMS Malware",
            "4": "Riskware",
            "5": "Benign"
        }
    }
    print("SHAP explainability configuration compiled.")
    return shap_meta


def main():
    """Main orchestrator for ML training pipeline."""
    # Directory setup
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "dynamic_features.csv"
    
    # 1. Load Data
    df = load_data(csv_path)
    
    # 2. Preprocess & Split
    X_train, X_test, y_train, y_test, feature_names = preprocess_and_split(df)
    
    # 3. Scaling
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
    
    # 4. Train Model
    model = train_model(X_train_scaled, y_train)
    
    # 5. Evaluate Model
    overall_acc = evaluate_model(model, X_test_scaled, y_test)
    
    # 6. SHAP Explainability Meta
    shap_meta = generate_shap_meta(model, X_test_scaled, feature_names)
    
    # 7. Save Artifacts
    model_path = base_dir / "model.joblib"
    scaler_path = base_dir / "scaler.joblib"
    feature_names_path = base_dir / "feature_names.json"
    shap_meta_path = base_dir / "shap_meta.json"
    
    print("\nSaving artifacts...")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    with open(feature_names_path, "w") as f:
        json.dump(feature_names, f, indent=2)
        
    with open(shap_meta_path, "w") as f:
        json.dump(shap_meta, f, indent=2)
        
    print("\n=== Final Training Summary ===")
    print(f"Model saved to: {model_path}")
    print(f"Scaler saved to: {scaler_path}")
    print(f"Feature count: {len(feature_names)}")
    print(f"Test Accuracy: {overall_acc * 100:.2f}%")


if __name__ == "__main__":
    main()
