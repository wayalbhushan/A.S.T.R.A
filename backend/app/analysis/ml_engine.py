"""
ASTRA ML Inference Engine
Loads trained model artifacts and predicts malware class from feature vectors.
"""

import json
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
import shap
import structlog

logger = structlog.get_logger()

# Resolve artifact paths using pathlib.Path (as specified in rule)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "ml" / "model.joblib"
SCALER_PATH = BASE_DIR / "ml" / "scaler.joblib"
FEATURE_NAMES_PATH = BASE_DIR / "ml" / "feature_names.json"
SHAP_META_PATH = BASE_DIR / "ml" / "shap_meta.json"

STATIC_MODEL_PATH = BASE_DIR / "ml" / "static_model.joblib"
STATIC_SCALER_PATH = BASE_DIR / "ml" / "static_scaler.joblib"
STATIC_FEATURE_NAMES_PATH = BASE_DIR / "ml" / "static_feature_names.json"
STATIC_SHAP_META_PATH = BASE_DIR / "ml" / "static_shap_meta.json"
STATIC_MODEL_META_PATH = BASE_DIR / "ml" / "static_model_meta.json"

# Check static model files exist on module import
if not (STATIC_MODEL_PATH.exists() and STATIC_SCALER_PATH.exists() and STATIC_FEATURE_NAMES_PATH.exists() and STATIC_SHAP_META_PATH.exists()):
    raise RuntimeError("Static model not found. Run train_static_model.py")

# Load static model artifacts globally on startup
try:
    static_model = joblib.load(STATIC_MODEL_PATH)
    static_scaler = joblib.load(STATIC_SCALER_PATH)
    with open(STATIC_FEATURE_NAMES_PATH, "r") as f:
        static_feature_names = json.load(f)
    with open(STATIC_SHAP_META_PATH, "r") as f:
        static_shap_meta = json.load(f)
    static_explainer = shap.TreeExplainer(static_model)
    logger.info("ML Engine successfully loaded and initialized static artifacts.")
except Exception as e:
    logger.exception("Failed to initialize ML Engine or load static model files", error=str(e))
    raise RuntimeError(f"Error loading static model files: {str(e)}")


def _check_static_artifact_version():
    """Validates sklearn version consistency between trained artifact and installed environment."""
    import sklearn
    if not STATIC_MODEL_META_PATH.exists():
        logger.warning("static_model_meta_missing", path=str(STATIC_MODEL_META_PATH))
        return
    try:
        with open(STATIC_MODEL_META_PATH, "r") as f:
            meta = json.load(f)
        meta_sklearn = meta.get("sklearn_version")
        installed_sklearn = sklearn.__version__
        if meta_sklearn != installed_sklearn:
            logger.warning(
                "static_model_version_mismatch",
                meta_version=meta_sklearn,
                installed_version=installed_sklearn
            )
    except Exception as e:
        logger.warning("static_model_meta_read_error", error=str(e))


_check_static_artifact_version()

# Dynamic model: lazy loaded on first call to predict()
_dynamic_loaded = False
model = None
scaler = None
feature_names = None
shap_meta = None
explainer = None


def _load_dynamic():
    """Lazily loads dynamic model artifacts on first predict() invocation."""
    global model, scaler, feature_names, shap_meta, explainer, _dynamic_loaded
    if _dynamic_loaded:
        return
    if not (MODEL_PATH.exists() and SCALER_PATH.exists() and FEATURE_NAMES_PATH.exists() and SHAP_META_PATH.exists()):
        raise RuntimeError("Model files not found. Run train_model.py first")
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        with open(FEATURE_NAMES_PATH, "r") as f:
            feature_names = json.load(f)
        with open(SHAP_META_PATH, "r") as f:
            shap_meta = json.load(f)
        explainer = shap.TreeExplainer(model)
        _dynamic_loaded = True
        logger.info("ML Engine successfully loaded dynamic model artifacts.")
    except Exception as e:
        logger.exception("Failed to initialize dynamic model artifacts", error=str(e))
        raise RuntimeError(f"Error loading model files: {str(e)}")


# Class mappings
CLASS_NAMES = {
    1: "Adware",
    2: "Banking Malware",
    3: "SMS Malware",
    4: "Riskware",
    5: "Benign"
}


def predict(feature_vector: dict) -> dict:
    """Classifies a feature vector of syscall/binder call frequencies.
    
    Args:
        feature_vector: dict mapping feature names (API/binder/syscall name) to frequency.
        
    Returns:
        dict containing predicted class, confidence, top contributing features (SHAP),
        and raw class probabilities.
        
    Raises:
        ValueError: If feature_vector is empty or None.
    """
    if not feature_vector:
        raise ValueError("Feature vector cannot be empty")

    if not _dynamic_loaded:
        _load_dynamic()

    # Step a: Build DataFrame with 1 row, filling missing features with 0
    row_dict = {name: float(feature_vector.get(name, 0.0)) for name in feature_names}
    row_df = pd.DataFrame([row_dict], columns=feature_names)

    # Step b: Scale the features
    scaled_row = scaler.transform(row_df)

    # Step c: Predict predicted class (int)
    pred_class_arr = model.predict(scaled_row)
    predicted_class = int(pred_class_arr[0])

    # Step d: Predict class probabilities and select confidence for predicted class
    probs = model.predict_proba(scaled_row)[0]
    class_classes = list(model.classes_)
    class_idx = class_classes.index(predicted_class)
    confidence = float(probs[class_idx])

    # Step e: SHAP computation wrapped in try/except (Task 2, Rule 5)
    top_features = []
    try:
        # Calculate SHAP values for the single row
        shap_values = explainer.shap_values(scaled_row)
        
        # Resolve multiclass representation from different SHAP versions dynamically
        if isinstance(shap_values, list):
            class_shap = shap_values[class_idx]
            if len(class_shap.shape) > 1:
                class_shap = class_shap[0]
        else:
            if len(shap_values.shape) == 3:
                class_shap = shap_values[0, :, class_idx]
            elif len(shap_values.shape) == 2:
                class_shap = shap_values[:, class_idx]
            else:
                class_shap = shap_values

        # Step f: Extract top 10 features by absolute SHAP value
        zipped_features = list(zip(feature_names, class_shap))
        sorted_features = sorted(zipped_features, key=lambda x: abs(x[1]), reverse=True)
        
        for feat, val in sorted_features[:10]:
            direction = "increases_risk" if val > 0 else "decreases_risk"
            top_features.append({
                "feature": feat,
                "shap_value": float(val),
                "direction": direction
            })
    except Exception as e:
        logger.warning("SHAP explanation extraction failed", error=str(e))
        top_features = []  # Fallback to empty if SHAP fails

    # Step g: Compile raw probabilities for all 5 target classes
    all_probabilities = {}
    for idx, cls in enumerate(class_classes):
        class_label = CLASS_NAMES.get(int(cls), "Unknown")
        all_probabilities[class_label] = float(probs[idx])

    return {
        "predicted_class": predicted_class,
        "class_name": CLASS_NAMES.get(predicted_class, "Unknown"),
        "confidence": round(confidence, 4),
        "top_features": top_features,
        "all_probabilities": all_probabilities
    }


def predict_static(feature_vector: dict) -> dict:
    """Classifies a static binary feature vector of permissions and API class names.
    
    Args:
        feature_vector: dict mapping static feature names to 0 or 1.
        
    Returns:
        dict containing predicted class, confidence, top contributing features (SHAP),
        and raw class probabilities.
        
    Raises:
        ValueError: If feature_vector is empty or None.
    """
    if not feature_vector:
        raise ValueError("Feature vector cannot be empty")

    # Build DataFrame with 1 row, filling missing features with 0
    row_dict = {name: float(feature_vector.get(name, 0.0)) for name in static_feature_names}
    row_df = pd.DataFrame([row_dict], columns=static_feature_names)

    # Scale the features
    scaled_row = static_scaler.transform(row_df)

    # Predict predicted class (int: 0 or 1)
    pred_class_arr = static_model.predict(scaled_row)
    predicted_class = int(pred_class_arr[0])

    # Predict class probabilities and select confidence for predicted class
    probs = static_model.predict_proba(scaled_row)[0]
    class_classes = list(static_model.classes_)
    class_idx = class_classes.index(predicted_class)
    confidence = float(probs[class_idx])

    # SHAP explainability
    STATIC_CLASS_NAMES = {0: "Goodware", 1: "Malware"}
    top_features = []
    try:
        # Calculate SHAP values for the single row
        shap_values = static_explainer.shap_values(scaled_row)
        
        # Resolve binary representation from SHAP
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class]
            if len(class_shap.shape) > 1:
                class_shap = class_shap[0]
        else:
            if len(shap_values.shape) == 3:
                class_shap = shap_values[0, :, predicted_class]
            elif len(shap_values.shape) == 2:
                class_shap = shap_values[:, predicted_class]
            else:
                class_shap = shap_values

        zipped_features = list(zip(static_feature_names, class_shap))
        sorted_features = sorted(zipped_features, key=lambda x: abs(x[1]), reverse=True)
        
        for feat, val in sorted_features[:10]:
            direction = "increases_risk" if val > 0 else "decreases_risk"
            top_features.append({
                "feature": feat,
                "shap_value": float(val),
                "direction": direction
            })
    except Exception as e:
        logger.warning("Static SHAP explanation extraction failed", error=str(e))
        top_features = []  # Fallback to empty if SHAP fails

    # Compile raw probabilities
    all_probabilities = {}
    for idx, cls in enumerate(class_classes):
        class_label = STATIC_CLASS_NAMES.get(int(cls), "Unknown")
        all_probabilities[class_label] = float(probs[idx])

    for label in ["Goodware", "Malware"]:
        if label not in all_probabilities:
            all_probabilities[label] = 0.0

    return {
        "predicted_class": predicted_class,
        "class_name": STATIC_CLASS_NAMES.get(predicted_class, "Unknown"),
        "confidence": round(confidence, 4),
        "top_features": top_features,
        "probabilities": all_probabilities
    }


if __name__ == "__main__":
    _load_dynamic()
    # Test execution with zero vector and arbitrary active syscalls (Task 2, Rule 6)
    test_vector_dyn = {name: 0 for name in feature_names}
    test_vector_dyn["open"] = 100
    test_vector_dyn["read"] = 50
    test_vector_dyn["write"] = 30
    
    result_dyn = predict(test_vector_dyn)
    print("Dynamic model test:")
    print(json.dumps(result_dyn, indent=2))

    # Test static model
    test_vector_stat = {name: 0 for name in static_feature_names}
    test_vector_stat['READ_SMS'] = 1
    test_vector_stat['SEND_SMS'] = 1
    test_vector_stat['READ_CONTACTS'] = 1
    test_vector_stat['INTERNET'] = 1
    test_vector_stat['RECEIVE_BOOT_COMPLETED'] = 1
    result_stat = predict_static(test_vector_stat)
    print("Static model test:")
    print(json.dumps(result_stat, indent=2))
