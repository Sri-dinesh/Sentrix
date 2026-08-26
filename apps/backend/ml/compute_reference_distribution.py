import os
import sys
import json
import joblib
import torch
import numpy as np

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.loaders import load_cicids2017
from ml.datasets.preprocessing import load_scaler, transform_features
from ml.train_autoencoder import NetworkAutoencoder
from app.core.storage import upload_model

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
AUTOENCODER_PATH = os.path.join(MODELS_DIR, "autoencoder.pt")
AE_META_PATH = os.path.join(MODELS_DIR, "autoencoder_meta.json")
REF_DIST_PATH = os.path.join(MODELS_DIR, "reference_distribution.joblib")


def compute_reference_distribution(sample_size: int = 2500):
    print("=== Phase 6: Computing Latent Space Reference Distribution ===")

    # 1. Load metadata & models
    with open(AE_META_PATH, "r", encoding="utf-8") as f:
        ae_meta = json.load(f)

    input_dim = ae_meta["input_dim"]
    latent_dim = ae_meta.get("latent_dim", 16)

    scaler = load_scaler(SCALER_PATH)
    autoencoder = NetworkAutoencoder(input_dim=input_dim, latent_dim=latent_dim)
    autoencoder.load_state_dict(torch.load(AUTOENCODER_PATH, weights_only=True))
    autoencoder.eval()

    # 2. Load benign training dataset
    X_benign, _, _ = load_cicids2017(benign_only=True)
    X_benign_scaled = transform_features(X_benign, scaler)

    # 3. Extract latent representations
    print(f"Extracting latent vectors from {len(X_benign)} benign flows...")
    with torch.no_grad():
        tensor = torch.from_numpy(X_benign_scaled).float()
        latent_embeddings = autoencoder.encode(tensor).numpy()

    # 4. Compute statistics
    mean_vec = np.mean(latent_embeddings, axis=0)
    cov_matrix = np.cov(latent_embeddings, rowvar=False)

    # Sample representative vectors for non-parametric 2-sample tests
    if len(latent_embeddings) > sample_size:
        indices = np.random.choice(len(latent_embeddings), size=sample_size, replace=False)
        reference_samples = latent_embeddings[indices]
    else:
        reference_samples = latent_embeddings

    ref_payload = {
        "latent_dim": latent_dim,
        "sample_count": len(reference_samples),
        "mean_vector": mean_vec,
        "covariance_matrix": cov_matrix,
        "reference_samples": reference_samples,
    }

    joblib.dump(ref_payload, REF_DIST_PATH)
    print(f"Reference distribution saved to: {REF_DIST_PATH}")
    print(f"Mean vector shape: {mean_vec.shape}, Reference samples: {reference_samples.shape}")

    # Mirror to storage
    upload_model(REF_DIST_PATH, "reference/v1.0.0/reference_distribution.joblib")
    return ref_payload


if __name__ == "__main__":
    compute_reference_distribution()
