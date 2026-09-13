from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import numpy as np
from app.domain.detection.autoencoder import AutoencoderModel
from app.domain.detection.classifier import ClassifierModel


@dataclass
class DetectionResult:
    anomaly_score: float
    is_anomalous: bool
    attack_type: Optional[str] = None
    classifier_margin: Optional[float] = None
    latent_vector: np.ndarray = field(default_factory=lambda: np.zeros(16))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "is_anomalous": self.is_anomalous,
            "attack_type": self.attack_type,
            "classifier_margin": self.classifier_margin,
        }


class DetectionService:
    """
    Orchestration service combining Autoencoder and Classifier models.
    Executes Autoencoder on all flows; conditionally executes Classifier only on anomalous flows.
    """

    def __init__(
        self,
        autoencoder: Optional[AutoencoderModel] = None,
        classifier: Optional[ClassifierModel] = None,
    ):
        self.autoencoder = autoencoder or AutoencoderModel()
        self.classifier = classifier or ClassifierModel()

    def score_flow(
        self,
        raw_features: np.ndarray,
        anomaly_threshold: Optional[float] = None,
    ) -> DetectionResult:
        """
        Scores a single network flow.
        1. Always runs autoencoder reconstruction & latent extraction.
        2. If reconstruction error > threshold, invokes XGBoost classifier.
        3. If benign, marks attack_type as 'BENIGN' without wasting compute.
        """
        # Step 1: Autoencoder scoring
        anomaly_score = self.autoencoder.score(raw_features)
        is_anomalous = self.autoencoder.is_anomalous(anomaly_score, threshold=anomaly_threshold)
        latent_vec = self.autoencoder.get_latent(raw_features)

        attack_type: Optional[str] = "BENIGN"
        classifier_margin: Optional[float] = 1.0

        # Step 2: Classifier execution on anomalies
        if is_anomalous:
            pred_attack, margin = self.classifier.predict(raw_features)
            attack_type = pred_attack
            classifier_margin = margin
            # If classifier flags as benign despite autoencoder anomaly, suppress attack confidence
            if pred_attack == "BENIGN":
                classifier_margin = 0.0

        return DetectionResult(
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            attack_type=attack_type,
            classifier_margin=classifier_margin,
            latent_vector=latent_vec,
        )


# Global singleton instance
_detection_service_instance: Optional[DetectionService] = None


def get_detection_service() -> DetectionService:
    global _detection_service_instance
    if _detection_service_instance is None:
        _detection_service_instance = DetectionService()
    return _detection_service_instance
