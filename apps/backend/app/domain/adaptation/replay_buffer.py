import os
import sys
import json
from typing import Tuple, List, Dict, Any, Optional
import numpy as np
from sqlalchemy.orm import Session

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.loaders import load_cicids2017
from app.models.incident import Incident
from app.models.flow import Flow

ACTIVE_LEARNING_POOL_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../../ml/datasets/active_learning_pool.json",
    )
)


class ReplayBuffer:
    """
    Replay Buffer for Continual Model Adaptation.
    Maintains a fixed-size historical baseline sample from training data combined
    with a growing dynamic pool of analyst-confirmed live feedback.
    
    Prevents catastrophic forgetting while adapting models to emerging attack patterns
    and enterprise traffic distribution drift.
    """

    def __init__(
        self,
        max_buffer_size: int = 10000,
        replay_ratio: float = 0.70,
        active_learning_file: str = ACTIVE_LEARNING_POOL_FILE,
    ) -> None:
        self.max_buffer_size = max_buffer_size
        self.replay_ratio = replay_ratio
        self.active_learning_file = active_learning_file

        # Historical baseline cache
        self._historical_X: Optional[np.ndarray] = None
        self._historical_y: Optional[np.ndarray] = None
        self._feature_names: List[str] = []

        # Dynamic memory pool for live/staged samples
        self._live_samples: List[Dict[str, Any]] = []
        self._load_historical_baseline()
        self._load_active_learning_pool()

    def _load_historical_baseline(self) -> None:
        """Loads historical training dataset."""
        try:
            X, y, feature_names = load_cicids2017(benign_only=False)
            self._historical_X = X
            self._historical_y = y
            self._feature_names = feature_names
        except Exception as e:
            print(f"Warning: Could not load historical baseline dataset: {e}")
            self._historical_X = np.empty((0, 78), dtype=np.float32)
            self._historical_y = np.empty((0,), dtype=object)

    def _load_active_learning_pool(self) -> None:
        """Loads analyst-verified feedback samples from disk."""
        if os.path.exists(self.active_learning_file):
            try:
                with open(self.active_learning_file, "r", encoding="utf-8") as f:
                    self._live_samples = json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load active learning pool: {e}")
                self._live_samples = []

    def add_sample(
        self,
        raw_features: Dict[str, Any],
        label: str = "BENIGN",
        persist: bool = True,
    ) -> None:
        """Adds a verified sample into the dynamic live pool."""
        record = {
            "verified_label": label,
            "raw_features": raw_features,
        }
        self._live_samples.append(record)
        if len(self._live_samples) > self.max_buffer_size:
            self._live_samples.pop(0)

        if persist:
            try:
                os.makedirs(os.path.dirname(self.active_learning_file), exist_ok=True)
                with open(self.active_learning_file, "w", encoding="utf-8") as f:
                    json.dump(self._live_samples, f, indent=2)
            except Exception as e:
                print(f"Warning: Failed to persist active learning sample: {e}")

    def sync_database_feedback(self, db: Session, limit: int = 500) -> int:
        """
        Synchronizes verified incident resolutions from the database into the live pool.
        Prioritizes flows marked as 'false_positive' by analysts.
        """
        resolved_incidents = (
            db.query(Incident)
            .filter(Incident.status.in_(["false_positive", "resolved"]))
            .order_by(Incident.created_at.desc())
            .limit(limit)
            .all()
        )

        added_count = 0
        for inc in resolved_incidents:
            if inc.detection and inc.detection.flow:
                flow: Flow = inc.detection.flow
                label = "BENIGN" if inc.status == "false_positive" else (inc.detection.attack_type or "BENIGN")
                if flow.raw_features:
                    self.add_sample(raw_features=flow.raw_features, label=label, persist=False)
                    added_count += 1

        if added_count > 0:
            try:
                with open(self.active_learning_file, "w", encoding="utf-8") as f:
                    json.dump(self._live_samples, f, indent=2)
            except Exception:
                pass

        return added_count

    def _convert_dict_to_vector(self, raw_features: Dict[str, Any]) -> np.ndarray:
        """Converts raw features dictionary to ordered numerical vector."""
        if not self._feature_names:
            # Fallback to length 78 zero-vector
            return np.zeros((78,), dtype=np.float32)

        vector = np.zeros((len(self._feature_names),), dtype=np.float32)
        for idx, feat_name in enumerate(self._feature_names):
            val = raw_features.get(feat_name, 0.0)
            try:
                vector[idx] = float(val) if val is not None else 0.0
            except (ValueError, TypeError):
                vector[idx] = 0.0
        return vector

    def get_training_batch(
        self,
        size: int = 500,
        replay_ratio: Optional[float] = None,
        benign_only: bool = False,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns a mixed sample batch containing:
        - `replay_ratio` portion of original historical baseline
        - `(1 - replay_ratio)` portion of recent live/analyst-feedback samples
        
        Guarantees exact batch size even if the live pool is sparse.
        """
        ratio = self.replay_ratio if replay_ratio is None else replay_ratio
        n_historical = int(size * ratio)
        n_live = size - n_historical

        # 1. Filter historical data
        hist_X = self._historical_X
        hist_y = self._historical_y
        if hist_X is None or len(hist_X) == 0:
            hist_X = np.zeros((100, len(self._feature_names) or 78), dtype=np.float32)
            hist_y = np.array(["BENIGN"] * 100, dtype=object)

        if benign_only:
            benign_mask = np.char.upper(hist_y.astype(str)) == "BENIGN"
            if np.any(benign_mask):
                hist_X = hist_X[benign_mask]
                hist_y = hist_y[benign_mask]

        # Sample historical portion
        hist_indices = np.random.choice(len(hist_X), size=n_historical, replace=(len(hist_X) < n_historical))
        X_hist = hist_X[hist_indices]
        y_hist = hist_y[hist_indices]

        # 2. Sample live pool portion
        live_candidates = self._live_samples
        if benign_only:
            live_candidates = [s for s in live_candidates if s.get("verified_label", "").upper() == "BENIGN"]

        if live_candidates and n_live > 0:
            sampled_live = np.random.choice(
                live_candidates,  # type: ignore[arg-type]
                size=n_live,
                replace=(len(live_candidates) < n_live),
            )
            X_live = np.array([self._convert_dict_to_vector(s["raw_features"]) for s in sampled_live], dtype=np.float32)
            y_live = np.array([s.get("verified_label", "BENIGN") for s in sampled_live], dtype=object)
        else:
            # If live pool is empty, backfill from historical baseline
            extra_indices = np.random.choice(len(hist_X), size=n_live, replace=(len(hist_X) < n_live))
            X_live = hist_X[extra_indices]
            y_live = hist_y[extra_indices]

        # Combine batches
        X_batch = np.vstack([X_hist, X_live])
        y_batch = np.concatenate([y_hist, y_live])

        # Shuffle joint batch
        shuffle_idx = np.random.permutation(len(X_batch))
        return X_batch[shuffle_idx], y_batch[shuffle_idx]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "historical_samples": len(self._historical_X) if self._historical_X is not None else 0,
            "live_feedback_samples": len(self._live_samples),
            "replay_ratio": self.replay_ratio,
            "feature_dim": len(self._feature_names),
        }


_replay_buffer_instance: Optional[ReplayBuffer] = None


def get_replay_buffer() -> ReplayBuffer:
    global _replay_buffer_instance
    if _replay_buffer_instance is None:
        _replay_buffer_instance = ReplayBuffer()
    return _replay_buffer_instance
