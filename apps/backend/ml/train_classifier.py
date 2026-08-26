import os
import sys
import json
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

# Ensure root backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.loaders import load_cicids2017, train_test_split_stratified
from ml.datasets.preprocessing import load_scaler, transform_features

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
os.makedirs(MODELS_DIR, exist_ok=True)
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "classifier.joblib")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")
CLASSIFIER_META_PATH = os.path.join(MODELS_DIR, "classifier_meta.json")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")


def train_classifier():
    print("=== Phase 4: Training XGBoost Multi-Class Flow Classifier ===")
    X, y, feature_names = load_cicids2017(benign_only=False)
    print(f"Loaded labeled dataset shape: {X.shape}, Samples count: {len(y)}")

    # Encode attack string labels to integers
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    classes = list(label_encoder.classes_)
    print(f"Attack classes ({len(classes)}): {classes}")

    # Stratified Train/Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split_stratified(
        X, y_encoded, test_size=0.2, random_state=42
    )

    # Standardize features using the saved scaler from Task 4.4
    scaler = load_scaler(SCALER_PATH)
    X_train_scaled = transform_features(X_train, scaler)
    X_test_scaled = transform_features(X_test, scaler)

    # Initialize and train XGBoost multi-class model
    print("Training XGBoost classifier...")
    clf = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        tree_method="hist",
    )

    clf.fit(
        X_train_scaled,
        y_train,
        eval_set=[(X_test_scaled, y_test)],
        verbose=False,
    )

    # Evaluate model predictions
    y_pred = clf.predict(X_test_scaled)
    y_probs = clf.predict_proba(X_test_scaled)

    # Compute classifier margins: gap between top-1 and top-2 predicted probabilities
    sorted_probs = np.sort(y_probs, axis=1)
    margins = sorted_probs[:, -1] - sorted_probs[:, -2]

    # Metrics
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    macro_precision = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    macro_recall = float(recall_score(y_test, y_pred, average="macro", zero_division=0))

    report = classification_report(
        y_test,
        y_pred,
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )
    conf_matrix = confusion_matrix(y_test, y_pred).tolist()

    print("\n[Classifier Evaluation Report]")
    print(f"Macro F1-Score:    {macro_f1:.4f}")
    print(f"Macro Precision:   {macro_precision:.4f}")
    print(f"Macro Recall:      {macro_recall:.4f}")
    print(f"Mean Margin:       {float(np.mean(margins)):.4f} (Median: {float(np.median(margins)):.4f})")

    for cls_name in classes:
        cls_metrics = report.get(cls_name, {})
        print(
            f"  - {cls_name:<28} | Precision: {cls_metrics.get('precision', 0):.4f} "
            f"| Recall: {cls_metrics.get('recall', 0):.4f} | F1: {cls_metrics.get('f1-score', 0):.4f}"
        )

    # Save model, label encoder, and metadata
    joblib.dump(clf, CLASSIFIER_PATH)
    joblib.dump(label_encoder, LABEL_ENCODER_PATH)

    meta = {
        "model_type": "XGBoost",
        "classes": classes,
        "n_classes": len(classes),
        "macro_f1": macro_f1,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "mean_margin": float(np.mean(margins)),
        "classification_report": report,
        "confusion_matrix": conf_matrix,
    }
    with open(CLASSIFIER_META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\nTrained classifier saved to: {CLASSIFIER_PATH}")
    print(f"Label encoder saved to: {LABEL_ENCODER_PATH}")
    print(f"Evaluation metrics saved to: {CLASSIFIER_META_PATH}")
    return clf, meta


if __name__ == "__main__":
    train_classifier()
