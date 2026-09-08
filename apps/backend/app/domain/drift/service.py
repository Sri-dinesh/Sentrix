from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.domain.drift.monitor import DriftMonitor, get_drift_monitor
from app.repositories import drift_repository


@dataclass
class DriftState:
    drift_score: float
    is_drifting: bool
    p_value: Optional[float]
    sample_count: int
    last_checked_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_score": self.drift_score,
            "is_drifting": self.is_drifting,
            "p_value": self.p_value,
            "sample_count": self.sample_count,
            "last_checked_at": self.last_checked_at.isoformat(),
        }


class DriftService:
    """
    Manages ongoing concept drift tracking and triggers alert/retraining thresholds.
    """

    def __init__(
        self,
        monitor: Optional[DriftMonitor] = None,
        drift_threshold: float = 0.25,
    ):
        self.monitor = monitor or get_drift_monitor()
        self.drift_threshold = drift_threshold
        self.last_state: Optional[DriftState] = None

    def observe(self, latent_vector: Any):
        """Passes a single latent vector to the drift monitor."""
        self.monitor.add_observation(latent_vector)

    def check_drift(
        self,
        db: Optional[Session] = None,
        threshold: Optional[float] = None,
    ) -> DriftState:
        """
        Evaluates current drift score from the rolling observation window.
        If drift score exceeds the critical threshold, persists a drift event into DB.
        """
        thresh = threshold if threshold is not None else self.drift_threshold
        score, p_val = self.monitor.compute_drift_score()

        # If insufficient samples in window, default to zero drift
        effective_score = float(score) if score is not None else 0.0
        is_drifting = effective_score >= thresh

        state = DriftState(
            drift_score=effective_score,
            is_drifting=is_drifting,
            p_value=p_val,
            sample_count=self.monitor.get_sample_count(),
            last_checked_at=datetime.now(timezone.utc),
        )
        self.last_state = state

        # If drifting and DB session provided, log drift event and queue adaptation
        if is_drifting and db is not None:
            triggered_retrain = False
            try:
                # Attempt to enqueue background adaptation task via Celery
                from app.worker.tasks import run_adaptation_cycle_task
                try:
                    run_adaptation_cycle_task.delay(trigger="concept_drift_detected", requested_by="drift_monitor")
                    triggered_retrain = True
                except Exception as celery_err:
                    print(f"Notice: Celery queue unavailable for automated drift adaptation: {celery_err}")

                drift_repository.record_drift_event(
                    db=db,
                    drift_score=effective_score,
                    triggered_retrain=triggered_retrain,
                )
            except Exception as e:
                print(f"Warning: Failed to record drift event: {e}")

        return state


# Global singleton instance
_drift_service_instance: Optional[DriftService] = None


def get_drift_service() -> DriftService:
    global _drift_service_instance
    if _drift_service_instance is None:
        _drift_service_instance = DriftService()
    return _drift_service_instance
