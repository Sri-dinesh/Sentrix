import os
import sys
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

# Ensure root backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.loaders import load_cicids2017, train_test_split_stratified
from ml.datasets.preprocessing import fit_and_save_scaler, transform_features

# Output checkpoint directories
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
os.makedirs(MODELS_DIR, exist_ok=True)
AUTOENCODER_PATH = os.path.join(MODELS_DIR, "autoencoder.pt")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
AE_METADATA_PATH = os.path.join(MODELS_DIR, "autoencoder_meta.json")


class NetworkAutoencoder(nn.Module):
    """
    Feed-forward PyTorch Autoencoder for network flow anomaly detection.
    Compresses input feature vector into a 16-dimensional latent representation.
    """

    def __init__(self, input_dim: int, latent_dim: int = 16):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, latent_dim),
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),
            nn.Linear(64, input_dim),
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Extracts latent bottleneck embedding."""
        return self.encoder(x)

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """Reconstructs feature vector from latent embedding."""
        return self.decoder(z)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encode(x)
        return self.decode(z)

    def get_reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Computes per-sample MSE reconstruction error."""
        reconstructed = self.forward(x)
        return torch.mean((x - reconstructed) ** 2, dim=1)


def train_autoencoder(
    epochs: int = 35,
    batch_size: int = 128,
    lr: float = 1e-3,
    percentile_threshold: float = 95.0,
):
    print("=== Phase 4: Training PyTorch Autoencoder on Benign Traffic ===")
    X, y, feature_names = load_cicids2017(benign_only=True)
    print(f"Loaded benign dataset shape: {X.shape}, Features count: {len(feature_names)}")

    # Split into train & validation sets
    X_train, X_val, _, _ = train_test_split_stratified(X, y, test_size=0.2, random_state=42)

    # Fit and persist the standard scaler
    scaler = fit_and_save_scaler(X_train, scaler_path=SCALER_PATH)
    X_train_scaled = transform_features(X_train, scaler)
    X_val_scaled = transform_features(X_val, scaler)

    input_dim = X_train_scaled.shape[1]
    model = NetworkAutoencoder(input_dim=input_dim, latent_dim=16)

    # Datasets and Loaders
    train_dataset = TensorDataset(torch.from_numpy(X_train_scaled).float())
    val_dataset = TensorDataset(torch.from_numpy(X_val_scaled).float())

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    criterion = nn.MSELoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=4)

    best_val_loss = float("inf")

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for (batch_x,) in train_loader:
            optimizer.zero_grad()
            recon = model(batch_x)
            loss = criterion(recon, batch_x)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)

        train_loss /= len(train_loader.dataset)

        # Validation
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for (batch_x,) in val_loader:
                recon = model(batch_x)
                loss = criterion(recon, batch_x)
                val_loss += loss.item() * batch_x.size(0)

        val_loss /= len(val_loader.dataset)
        scheduler.step(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), AUTOENCODER_PATH)

        if epoch % 5 == 0 or epoch == epochs:
            print(f"Epoch [{epoch:02d}/{epochs:02d}] | Train Loss: {train_loss:.6f} | Val Loss: {val_loss:.6f}")

    # Load best checkpoint
    model.load_state_dict(torch.load(AUTOENCODER_PATH))
    model.eval()

    # Compute reconstruction errors on validation set to calibrate anomaly threshold
    with torch.no_grad():
        val_tensor = torch.from_numpy(X_val_scaled).float()
        val_errors = model.get_reconstruction_error(val_tensor).numpy()

    anomaly_threshold = float(np.percentile(val_errors, percentile_threshold))
    mean_val_error = float(np.mean(val_errors))
    std_val_error = float(np.std(val_errors))

    print(f"\n[Calibration Results]")
    print(f"Validation Reconstruction Error Mean: {mean_val_error:.6f} (Std: {std_val_error:.6f})")
    print(f"Calibrated Anomaly Threshold ({percentile_threshold}th percentile): {anomaly_threshold:.6f}")

    # Save metadata
    meta = {
        "input_dim": input_dim,
        "latent_dim": 16,
        "feature_names": feature_names,
        "anomaly_threshold": anomaly_threshold,
        "percentile_used": percentile_threshold,
        "mean_error": mean_val_error,
        "std_error": std_val_error,
        "best_val_loss": best_val_loss,
    }
    with open(AE_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Model saved to: {AUTOENCODER_PATH}")
    print(f"Metadata saved to: {AE_METADATA_PATH}")
    return model, meta


if __name__ == "__main__":
    train_autoencoder()
