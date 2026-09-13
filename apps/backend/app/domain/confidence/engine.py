import math
from dataclasses import dataclass
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.domain.confidence.tiers import Tier, classify_tier, get_recommended_action
from app.repositories import settings_repository


@dataclass
class ConfidenceScore:
    score: float
    tier: Tier
    recommended_action: str
    breakdown: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "tier": self.tier.value,
            "recommended_action": self.recommended_action,
            "breakdown": self.breakdown,
        }


class ConfidenceEngine:
    """
    Confidence Fusion Engine.
    Combines Autoencoder reconstruction anomaly score, XGBoost classifier margin,
    and Concept Drift penalty into a single calibrated confidence score with explainable breakdown.
    """

    def __init__(self, settings_dict: Optional[Dict[str, float]] = None):
        self._static_settings = settings_dict

    def _get_active_settings(self, db: Optional[Session] = None) -> Dict[str, float]:
        if self._static_settings:
            return self._static_settings
        return settings_repository.get_settings_dict(db)

    @staticmethod
    def normalize_anomaly_score(
        anomaly_score: float,
        threshold: float = 0.026147,
        k: float = 3.0,
    ) -> float:
        """
        Sigmoid normalization scaling reconstruction error relative to threshold:
        - When anomaly_score == threshold: normalized_score = 0.50
        - When anomaly_score >> threshold: normalized_score -> 1.00
        - When anomaly_score << threshold: normalized_score -> 0.00
        """
        if threshold <= 0:
            threshold = 0.026147

        ratio = anomaly_score / threshold
        # Continuous logistic curve centered at threshold (ratio = 1.0)
        norm_val = 1.0 / (1.0 + math.exp(-k * (ratio - 1.0)))
        return float(max(0.0, min(1.0, norm_val)))

    def calculate(
        self,
        anomaly_score: float,
        classifier_margin: Optional[float] = 1.0,
        drift_score: Optional[float] = 0.0,
        is_anomalous: bool = True,
        db: Optional[Session] = None,
    ) -> ConfidenceScore:
        """
        Calculates confidence score and maps to response tier.
        """
        cfg = self._get_active_settings(db)
        w_anomaly = cfg.get("confidence_weight_anomaly", 0.40)
        w_clf = cfg.get("confidence_weight_classifier", 0.40)
        w_drift = cfg.get("confidence_weight_drift", 0.20)
        base_thresh = cfg.get("anomaly_base_threshold", 0.026147)
        tier_high = cfg.get("tier_high_threshold", 0.85)
        tier_med = cfg.get("tier_medium_threshold", 0.50)

        # Normalize inputs
        norm_anomaly = self.normalize_anomaly_score(anomaly_score, threshold=base_thresh)
        eff_margin = float(classifier_margin) if classifier_margin is not None else 0.5
        eff_drift = float(drift_score) if drift_score is not None else 0.0

        # Component contributions (normalized so positive weights sum to 1.0)
        pos_weight = w_anomaly + w_clf
        norm_w_anomaly = (w_anomaly / pos_weight) if pos_weight > 0 else 0.5
        norm_w_clf = (w_clf / pos_weight) if pos_weight > 0 else 0.5

        anomaly_contrib = norm_w_anomaly * norm_anomaly
        classifier_contrib = norm_w_clf * eff_margin
        drift_penalty = w_drift * eff_drift

        # Multi-signal fusion
        raw_confidence = anomaly_contrib + classifier_contrib - drift_penalty
        final_score = float(max(0.0, min(1.0, raw_confidence)))

        # If flow was evaluated as completely non-anomalous benign traffic
        if not is_anomalous:
            final_score = min(final_score, 0.25)

        # Classify tier
        tier = classify_tier(
            final_score,
            tier_high_threshold=tier_high,
            tier_medium_threshold=tier_med,
        )
        action = get_recommended_action(tier)

        breakdown = {
            "weights": {
                "w1_anomaly": w_anomaly,
                "w2_classifier": w_clf,
                "w3_drift": w_drift,
            },
            "components": {
                "anomaly_contribution": round(anomaly_contrib, 4),
                "classifier_contribution": round(classifier_contrib, 4),
                "drift_penalty": round(drift_penalty, 4),
            },
            "raw_inputs": {
                "raw_anomaly_score": float(anomaly_score),
                "normalized_anomaly": round(norm_anomaly, 4),
                "classifier_margin": round(eff_margin, 4),
                "drift_score": round(eff_drift, 4),
                "anomaly_threshold_used": base_thresh,
            },
        }

        return ConfidenceScore(
            score=round(final_score, 4),
            tier=tier,
            recommended_action=action,
            breakdown=breakdown,
        )


# Global singleton instance
_confidence_engine_instance: Optional[ConfidenceEngine] = None


def get_confidence_engine() -> ConfidenceEngine:
    global _confidence_engine_instance
    if _confidence_engine_instance is None:
        _confidence_engine_instance = ConfidenceEngine()
    return _confidence_engine_instance
