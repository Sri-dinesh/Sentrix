import os
import json
import torch
import numpy as np
from typing import Optional
from app.core.storage import download_model
from ml.train_autoencoder import NetworkAutoencoder
from ml.datasets.preprocessing import load_scaler, transform_features


class AutoencoderModel:
    """
    Inference wrapper for the PyTorch Network Autoencoder.
    Computes reconstruction error and extracts latent embeddings for drift detection.
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        base_threshold: float = 0.026147,
    ):
        self.base_threshold = base_threshold
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Resolve scaler path
        if not scaler_path:
            scaler_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/scaler.joblib")
            )
        self.scaler = load_scaler(scaler_path)

        # Resolve model checkpoint path
        if not storage_path:
            storage_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/autoencoder.pt")
            )

        if not os.path.exists(storage_path):
            local_dest = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../ml/models/active_autoencoder.pt")
            )
            storage_path = download_model(storage_path, local_dest)

        # Load metadata if present
        meta_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../ml/models/autoencoder_meta.json")
        )
        input_dim = 71
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                input_dim = meta.get("input_dim", 71)
                self.base_threshold = meta.get("anomaly_threshold", base_threshold)

        self.model = NetworkAutoencoder(input_dim=input_dim, latent_dim=16)
        self.model.load_state_dict(
            torch.load(storage_path, map_location=self.device, weights_only=True)
        )
        self.model.to(self.device)
        self.model.eval()

    def score(self, raw_features: np.ndarray) -> float:
        """
        Computes the reconstruction error for a single flow feature vector.
        """
        features_2d = (
            raw_features.reshape(1, -1) if raw_features.ndim == 1 else raw_features
        )
        scaled_features = transform_features(features_2d, self.scaler)

        with torch.no_grad():
            tensor = torch.from_numpy(scaled_features).float().to(self.device)
            error = self.model.get_reconstruction_error(tensor).item()
        return float(error)

    def get_latent(self, raw_features: np.ndarray) -> np.ndarray:
        """
        Extracts 16-dimensional bottleneck latent embedding for concept drift monitoring.
        """
        features_2d = (
            raw_features.reshape(1, -1) if raw_features.ndim == 1 else raw_features
        )
        scaled_features = transform_features(features_2d, self.scaler)

        with torch.no_grad():
            tensor = torch.from_numpy(scaled_features).float().to(self.device)
            latent = self.model.encode(tensor).cpu().numpy()
        return latent.flatten()

    def is_anomalous(
        self,
        score: float,
        threshold: Optional[float] = None,
    ) -> bool:
        """
        Checks whether reconstruction score exceeds anomaly threshold.
        """
        active_thresh = threshold if threshold is not None else self.base_threshold
        return score > active_thresh
