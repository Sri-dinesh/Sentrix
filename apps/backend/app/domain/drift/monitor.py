import os
import joblib
import numpy as np
from collections import deque
from typing import Optional, Tuple
from scipy.stats import ks_2samp
from app.core.storage import download_model


class DriftMonitor:
    """
    Concept Drift Monitor tracking distributional shifts in network flow embeddings.
    Evaluates rolling observations against the baseline latent reference distribution using
    Kolmogorov-Smirnov two-sample tests and Population Stability Index (PSI).
    """

    def __init__(
        self,
        reference_path: Optional[str] = None,
        window_size: int = 300,
        min_samples: int = 40,
    ):
        self.window_size = window_size
        self.min_samples = min_samples
        self.observation_window: deque = deque(maxlen=window_size)

        # Resolve reference distribution
        if not reference_path:
            reference_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../ml/models/reference_distribution.joblib",
                )
            )

        if not os.path.exists(reference_path):
            local_dest = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../ml/models/active_reference_distribution.joblib",
                )
            )
            reference_path = download_model(reference_path, local_dest)

        ref_data = joblib.load(reference_path)
        self.reference_samples: np.ndarray = ref_data["reference_samples"]
        self.latent_dim: int = ref_data.get("latent_dim", 16)
        self.mean_vector: np.ndarray = ref_data["mean_vector"]

    def add_observation(self, latent_vector: np.ndarray):
        """
        Appends a newly observed latent vector to the rolling FIFO window.
        """
        vec = latent_vector.flatten()
        if len(vec) == self.latent_dim:
            self.observation_window.append(vec)

    def add_observations(self, latent_vectors: np.ndarray):
        """
        Batch adds observations.
        """
        for vec in latent_vectors:
            self.add_observation(vec)

    def get_sample_count(self) -> int:
        return len(self.observation_window)

    def clear(self):
        self.observation_window.clear()

    @staticmethod
    def calculate_psi(
        reference: np.ndarray,
        current: np.ndarray,
        num_buckets: int = 10,
    ) -> float:
        """
        Computes Population Stability Index (PSI) between reference and current 1D distributions.
        """
        percentiles = np.linspace(0, 100, num_buckets + 1)
        bucket_edges = np.percentile(reference, percentiles)
        bucket_edges = np.unique(bucket_edges)
        if len(bucket_edges) < 3:
            return 0.0

        bucket_edges[0] = -np.inf
        bucket_edges[-1] = np.inf

        ref_counts, _ = np.histogram(reference, bins=bucket_edges)
        cur_counts, _ = np.histogram(current, bins=bucket_edges)

        ref_pct = (ref_counts + 1e-5) / (len(reference) + 1e-5 * len(ref_counts))
        cur_pct = (cur_counts + 1e-5) / (len(current) + 1e-5 * len(cur_counts))

        psi_val = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
        return float(np.clip(psi_val, 0.0, 5.0))

    def compute_drift_score(self) -> Tuple[Optional[float], Optional[float]]:
        """
        Computes the current concept drift score and average KS p-value.
        Returns: (drift_score [0.0, 1.0], p_value)
        If observations < min_samples, returns (None, None).
        """
        if len(self.observation_window) < self.min_samples:
            return None, None

        current_samples = np.array(self.observation_window)

        dim_drift_scores = []
        p_values = []

        for dim in range(self.latent_dim):
            ref_dim = self.reference_samples[:, dim]
            cur_dim = current_samples[:, dim]

            # 2-sample KS test
            ks_res = ks_2samp(ref_dim, cur_dim)
            p_val = ks_res.pvalue
            p_values.append(p_val)

            # Significance weight: (1 - p_val) reflects confidence in distribution difference
            significance = max(0.0, 1.0 - p_val)
            dim_drift = ks_res.statistic * significance
            dim_drift_scores.append(dim_drift)

        mean_drift = float(np.mean(dim_drift_scores))
        mean_p_value = float(np.mean(p_values))

        # Normalized drift metric bounded between 0.0 and 1.0
        drift_score = float(np.clip(mean_drift, 0.0, 1.0))
        return drift_score, mean_p_value


# Global singleton instance
_drift_monitor_instance: Optional[DriftMonitor] = None


def get_drift_monitor() -> DriftMonitor:
    global _drift_monitor_instance
    if _drift_monitor_instance is None:
        _drift_monitor_instance = DriftMonitor()
    return _drift_monitor_instance
