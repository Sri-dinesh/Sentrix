import os
import sys
import json
import joblib
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

# Ensure root backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.loaders import load_cicids2017, train_test_split_stratified
from ml.datasets.preprocessing import load_scaler, transform_features
from ml.train_autoencoder import NetworkAutoencoder

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "results"))
os.makedirs(RESULTS_DIR, exist_ok=True)

AUTOENCODER_PATH = os.path.join(MODELS_DIR, "autoencoder.pt")
AE_META_PATH = os.path.join(MODELS_DIR, "autoencoder_meta.json")
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "classifier.joblib")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
EVAL_RESULTS_PATH = os.path.join(RESULTS_DIR, "evaluation_baseline.json")


def evaluate_pipeline():
    print("=== Phase 4: End-to-End Pipeline Evaluation (Autoencoder + Classifier) ===")
    
    # 1. Load artifacts
    with open(AE_META_PATH, "r", encoding="utf-8") as f:
        ae_meta = json.load(f)
    
    input_dim = ae_meta["input_dim"]
    anomaly_threshold = ae_meta["anomaly_threshold"]
    
    autoencoder = NetworkAutoencoder(input_dim=input_dim, latent_dim=16)
    autoencoder.load_state_dict(torch.load(AUTOENCODER_PATH))
    autoencoder.eval()

    classifier = joblib.load(CLASSIFIER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    scaler = load_scaler(SCALER_PATH)

    # 2. Load full test dataset
    X, y, feature_names = load_cicids2017(benign_only=False)
    _, X_test, _, y_test = train_test_split_stratified(X, y, test_size=0.2, random_state=42)
    X_test_scaled = transform_features(X_test, scaler)

    print(f"Evaluating across {len(y_test)} held-out flow records...")

    # 3. Step 1: Anomaly Scoring via Autoencoder
    with torch.no_grad():
        test_tensor = torch.from_numpy(X_test_scaled).float()
        recon_errors = autoencoder.get_reconstruction_error(test_tensor).numpy()

    is_anomalous = recon_errors > anomaly_threshold

    # 4. Step 2: Supervised Attack Categorization & Margin Computation
    y_test_binary = np.array([0 if label == "BENIGN" else 1 for label in y_test])
    y_pred_binary = is_anomalous.astype(int)

    # Binary Anomaly Detection Metrics
    tp = int(np.sum((y_test_binary == 1) & (y_pred_binary == 1)))
    fp = int(np.sum((y_test_binary == 0) & (y_pred_binary == 1)))
    tn = int(np.sum((y_test_binary == 0) & (y_pred_binary == 0)))
    fn = int(np.sum((y_test_binary == 1) & (y_pred_binary == 0)))

    det_precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    det_recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    det_f1 = float(2 * det_precision * det_recall / (det_precision + det_recall)) if (det_precision + det_recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Multi-class predictions for anomalous flows
    y_pred_multiclass = np.array(["BENIGN"] * len(y_test), dtype=object)
    anomalous_indices = np.where(is_anomalous)[0]

    if len(anomalous_indices) > 0:
        X_anomalous = X_test_scaled[anomalous_indices]
        clf_preds = classifier.predict(X_anomalous)
        y_pred_multiclass[anomalous_indices] = label_encoder.inverse_transform(clf_preds)

    multiclass_f1 = float(f1_score(y_test, y_pred_multiclass, average="macro", zero_division=0))
    multiclass_report = classification_report(y_test, y_pred_multiclass, output_dict=True, zero_division=0)

    print("\n" + "=" * 60)
    print("           SENTRIX PIPELINE BENCHMARK METRICS")
    print("=" * 60)
    print(f"Total Test Samples:             {len(y_test)}")
    print(f"Anomaly Detection Precision:     {det_precision:.4f}")
    print(f"Anomaly Detection Recall (TPR):  {det_recall:.4f}")
    print(f"Anomaly Detection F1-Score:      {det_f1:.4f}")
    print(f"False Positive Rate (FPR):       {fpr:.4f}")
    print(f"False Negative Rate (FNR):       {fnr:.4f}")
    print(f"Multi-Class End-to-End F1:       {multiclass_f1:.4f}")
    print("-" * 60)
    print("Confusion Matrix (Binary Detection):")
    print(f"  True Positives (Attacks Flagged):  {tp:>5}")
    print(f"  False Positives (Benign Flagged):  {fp:>5}")
    print(f"  True Negatives (Benign Passed):   {tn:>5}")
    print(f"  False Negatives (Attacks Missed): {fn:>5}")
    print("=" * 60)

    results = {
        "dataset": "CICIDS2017_sample",
        "n_samples": len(y_test),
        "anomaly_threshold": anomaly_threshold,
        "binary_metrics": {
            "precision": det_precision,
            "recall": det_recall,
            "f1_score": det_f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        },
        "multiclass_metrics": {
            "macro_f1": multiclass_f1,
            "detailed_report": multiclass_report,
        },
    }

    with open(EVAL_RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nBaseline results saved to: {EVAL_RESULTS_PATH}")
    return results


if __name__ == "__main__":
    evaluate_pipeline()
