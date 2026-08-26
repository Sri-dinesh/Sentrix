import os
import joblib
import numpy as np
from typing import Optional, Tuple
from app.core.storage import download_model
from ml.datasets.preprocessing import load_scaler, transform_features


class ClassifierModel:
    """
    Inference wrapper for the XGBoost Multi-Class Flow Classifier.
    Predicts attack category and computes classifier confidence margin.
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        label_encoder_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
    ):
        # Resolve scaler path
        if not scaler_path:
            scaler_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/scaler.joblib")
            )
        self.scaler = load_scaler(scaler_path)

        # Resolve label encoder path
        if not label_encoder_path:
            label_encoder_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/label_encoder.joblib")
            )
        self.label_encoder = joblib.load(label_encoder_path)

        # Resolve classifier model path
        if not storage_path:
            storage_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/classifier.joblib")
            )

        if not os.path.exists(storage_path):
            local_dest = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/active_classifier.joblib")
            )
            storage_path = download_model(storage_path, local_dest)

        self.model = joblib.load(storage_path)

    def predict(self, raw_features: np.ndarray) -> Tuple[str, float]:
        """
        Predicts attack classification label and computes margin between top-1 and top-2 probabilities.
        Returns: (attack_type, classifier_margin)
        """
        features_2d = (
            raw_features.reshape(1, -1) if raw_features.ndim == 1 else raw_features
        )
        scaled_features = transform_features(features_2d, self.scaler)

        probabilities = self.model.predict_proba(scaled_features)[0]
        top_indices = np.argsort(probabilities)[::-1]

        top_1_idx = top_indices[0]
        top_2_idx = top_indices[1] if len(top_indices) > 1 else top_1_idx

        top_1_prob = probabilities[top_1_idx]
        top_2_prob = probabilities[top_2_idx] if len(top_indices) > 1 else 0.0

        # Margin: confidence gap [0, 1]
        margin = float(top_1_prob - top_2_prob) if len(top_indices) > 1 else float(top_1_prob)
        margin = float(np.clip(margin, 0.0, 1.0))

        predicted_class_idx = int(top_1_idx)
        attack_type = str(self.label_encoder.inverse_transform([predicted_class_idx])[0])

        return attack_type, margin
