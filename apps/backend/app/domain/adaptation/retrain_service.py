import os
import sys
import time
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report
from sqlalchemy.orm import Session

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.models.model_version import ModelVersion
from app.repositories import model_repository
from app.core.storage import upload_model, download_model
from app.domain.adaptation.replay_buffer import get_replay_buffer, ReplayBuffer
from ml.train_autoencoder import NetworkAutoencoder
from ml.datasets.loaders import load_cicids2017, train_test_split_stratified
from ml.datasets.preprocessing import load_scaler, transform_features

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml/models"))
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
AE_META_PATH = os.path.join(MODELS_DIR, "autoencoder_meta.json")
CLASSIFIER_META_PATH = os.path.join(MODELS_DIR, "classifier_meta.json")


@dataclass
class RetrainResult:
    """Outcome and forensic audit log of an adaptation retraining attempt."""
    component: str  # "autoencoder" | "classifier"
    promoted: bool
    previous_version_tag: Optional[str]
    candidate_version_tag: str
    previous_metrics: Dict[str, Any]
    candidate_metrics: Dict[str, Any]
    rejection_reason: Optional[str] = None
    applied_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "promoted": self.promoted,
            "previous_version_tag": self.previous_version_tag,
            "candidate_version_tag": self.candidate_version_tag,
            "previous_metrics": self.previous_metrics,
            "candidate_metrics": self.candidate_metrics,
            "rejection_reason": self.rejection_reason,
            "applied_at": self.applied_at,
        }


class RetrainService:
    """
    Automated Continuous Model Retraining Service with Strict Regression Safety Gates.
    Fine-tunes neural autoencoders and gradient-boosted trees against replay batches,
    evaluates candidates on a fixed held-out benchmark, and gates promotion to production.
    """

    def __init__(self, replay_buffer: Optional[ReplayBuffer] = None) -> None:
        self.replay_buffer = replay_buffer or get_replay_buffer()
        self._scaler = None
        self._held_out_val_set = None

    def _get_scaler(self):
        if self._scaler is None:
            self._scaler = load_scaler(SCALER_PATH)
        return self._scaler

    def _get_held_out_validation_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Loads the uncontaminated, fixed benchmark evaluation set (identical to Phase 4 test split).
        This fixed validation set is NEVER sampled by the replay buffer.
        """
        if self._held_out_val_set is None:
            X, y, _ = load_cicids2017(benign_only=False)
            _, X_test, _, y_test = train_test_split_stratified(X, y, test_size=0.2, random_state=42)
            scaler = self._get_scaler()
            X_test_scaled = transform_features(X_test, scaler)
            self._held_out_val_set = (X_test, X_test_scaled, y_test, scaler)
        return self._held_out_val_set

    def retrain_autoencoder(
        self,
        db: Session,
        epochs: int = 4,
        lr: float = 1e-4,
        batch_size: int = 64,
        safety_margin: float = 0.05,  # Max allowed val loss degradation (5%)
        training_batch_size: int = 1000,
        custom_batch: Optional[Tuple[np.ndarray, np.ndarray]] = None,
    ) -> RetrainResult:
        """
        Fine-tunes the production Autoencoder on recent benign traffic.
        Evaluates reconstruction error on the held-out validation benchmark.
        Promotes only if validation loss does not degrade beyond safety_margin.
        """
        scaler = self._get_scaler()
        _, X_val_scaled, y_val, _ = self._get_held_out_validation_data()

        # 1. Retrieve currently active model metadata from DB or fallback
        active_rec = model_repository.get_active_model(db, component="autoencoder")
        prev_version_tag = active_rec.version_tag if active_rec else "v1.0.0"
        prev_metrics = active_rec.metrics if (active_rec and active_rec.metrics) else {}

        baseline_val_loss = float(prev_metrics.get("best_val_loss") or 0.015)

        # 2. Load current model weights
        input_dim = X_val_scaled.shape[1]
        model = NetworkAutoencoder(input_dim=input_dim, latent_dim=16)

        local_weights_path = os.path.join(MODELS_DIR, "autoencoder.pt")
        if active_rec and active_rec.storage_path:
            try:
                download_model(active_rec.storage_path, local_weights_path)
            except Exception:
                pass

        if os.path.exists(local_weights_path):
            model.load_state_dict(torch.load(local_weights_path, weights_only=True))

        # 3. Pull fine-tuning batch from replay buffer (or use custom test batch)
        if custom_batch is not None:
            X_train, _ = custom_batch
        else:
            X_train, _ = self.replay_buffer.get_training_batch(
                size=training_batch_size,
                benign_only=True,
            )

        X_train_scaled = transform_features(X_train, scaler)

        train_dataset = TensorDataset(torch.from_numpy(X_train_scaled).float())
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        criterion = nn.MSELoss()
        optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

        # Evaluate pre-retraining baseline on held-out validation benchmark
        benign_val_mask = np.array([str(val).strip().upper() == "BENIGN" for val in y_val], dtype=bool)
        X_val_benign = X_val_scaled[benign_val_mask]
        model.eval()
        with torch.no_grad():
            init_val_tensor = torch.from_numpy(X_val_benign).float()
            init_recon = model(init_val_tensor)
            baseline_val_loss = float(criterion(init_recon, init_val_tensor).item())

        # 4. Fine-tuning loop (freeze BatchNorm running statistics to prevent batch drift during fine-tuning)
        model.train()
        for m in model.modules():
            if isinstance(m, nn.BatchNorm1d):
                m.eval()

        for epoch in range(1, epochs + 1):
            for (batch_x,) in train_loader:
                optimizer.zero_grad()
                recon = model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()

        # 5. Evaluate candidate model on fixed held-out validation set
        benign_val_mask = np.array([str(val).strip().upper() == "BENIGN" for val in y_val], dtype=bool)
        X_val_benign = X_val_scaled[benign_val_mask]

        model.eval()
        with torch.no_grad():
            val_tensor = torch.from_numpy(X_val_benign).float()
            val_recon = model(val_tensor)
            candidate_val_loss = float(criterion(val_recon, val_tensor).item())
            recon_errors = model.get_reconstruction_error(val_tensor).numpy()
            candidate_threshold = float(np.percentile(recon_errors, 95.0))

        candidate_metrics = {
            "best_val_loss": candidate_val_loss,
            "anomaly_threshold": candidate_threshold,
            "mean_error": float(np.mean(recon_errors)),
            "input_dim": input_dim,
            "latent_dim": 16,
        }

        # 6. Safety Gate Evaluation
        max_allowed_loss = baseline_val_loss * (1.0 + safety_margin)
        candidate_tag = f"v{int(time.time())}.ae"

        if candidate_val_loss > max_allowed_loss:
            reason = (
                f"Candidate validation loss ({candidate_val_loss:.5f}) exceeded maximum allowed "
                f"threshold ({max_allowed_loss:.5f}) under {safety_margin:.1%} safety margin."
            )
            print(f"[Safety Gate REJECTED] {reason}")
            return RetrainResult(
                component="autoencoder",
                promoted=False,
                previous_version_tag=prev_version_tag,
                candidate_version_tag=candidate_tag,
                previous_metrics=prev_metrics,
                candidate_metrics=candidate_metrics,
                rejection_reason=reason,
            )

        # 7. Promotion to Production
        os.makedirs(MODELS_DIR, exist_ok=True)
        checkpoint_filename = f"autoencoder_{candidate_tag}.pt"
        checkpoint_path = os.path.join(MODELS_DIR, checkpoint_filename)
        torch.save(model.state_dict(), checkpoint_path)

        # Also update active local weights pointer
        torch.save(model.state_dict(), local_weights_path)

        remote_storage_path = upload_model(
            checkpoint_path, f"autoencoder/{candidate_tag}/{checkpoint_filename}"
        )

        model_repository.register_model_version(
            db=db,
            component="autoencoder",
            version_tag=candidate_tag,
            storage_path=remote_storage_path,
            metrics=candidate_metrics,
            set_active=True,
        )

        print(f"[Safety Gate PASSED] Promoted autoencoder {candidate_tag} (val_loss: {candidate_val_loss:.5f} <= {max_allowed_loss:.5f})")
        return RetrainResult(
            component="autoencoder",
            promoted=True,
            previous_version_tag=prev_version_tag,
            candidate_version_tag=candidate_tag,
            previous_metrics=prev_metrics,
            candidate_metrics=candidate_metrics,
        )

    def retrain_classifier(
        self,
        db: Session,
        safety_margin: float = 0.02,  # Max allowed drop in Macro F1 (2 percentage points)
        training_batch_size: int = 1500,
        custom_batch: Optional[Tuple[np.ndarray, np.ndarray]] = None,
    ) -> RetrainResult:
        """
        Fine-tunes the XGBoost multi-class attack classifier on mixed replay batches.
        Evaluates Macro F1 on the held-out validation benchmark.
        Promotes only if candidate Macro F1 doesn't drop below (baseline_f1 - safety_margin).
        """
        scaler = self._get_scaler()
        _, X_val_scaled, y_val, _ = self._get_held_out_validation_data()

        # 1. Retrieve currently active model metadata from DB or fallback
        active_rec = model_repository.get_active_model(db, component="classifier")
        prev_version_tag = active_rec.version_tag if active_rec else "v1.0.0"
        prev_metrics = active_rec.metrics if (active_rec and active_rec.metrics) else {}

        baseline_f1 = float(prev_metrics.get("macro_f1") or 0.83)

        # 2. Load LabelEncoder
        label_encoder_path = os.path.join(MODELS_DIR, "label_encoder.joblib")
        label_encoder: LabelEncoder = joblib.load(label_encoder_path)
        known_classes = set(label_encoder.classes_)

        # 3. Pull training batch from replay buffer (or use custom test batch)
        if custom_batch is not None:
            X_train, y_train = custom_batch
        else:
            X_train, y_train = self.replay_buffer.get_training_batch(
                size=training_batch_size,
                benign_only=False,
            )

        # Filter out unknown classes if any
        valid_mask = np.isin(y_train, list(known_classes))
        if np.any(valid_mask):
            X_train = X_train[valid_mask]
            y_train = y_train[valid_mask]

        # Ensure all known classes are present in training batch so XGBoost multi:softprob has full label range
        for cls_name in known_classes:
            if cls_name not in y_train:
                if self.replay_buffer._historical_y is not None:
                    match_idx = np.where(self.replay_buffer._historical_y == cls_name)[0]
                    if len(match_idx) > 0:
                        X_train = np.vstack([X_train, self.replay_buffer._historical_X[match_idx[:2]]])
                        y_train = np.concatenate([y_train, self.replay_buffer._historical_y[match_idx[:2]]])

        X_train_scaled = transform_features(X_train, scaler)
        y_train_encoded = label_encoder.transform(y_train)

        # 4. Train candidate XGBoost classifier
        candidate_clf = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=42,
            tree_method="hist",
        )

        candidate_clf.fit(X_train_scaled, y_train_encoded, verbose=False)

        # 5. Evaluate on fixed held-out validation set
        val_mask = np.isin(y_val, list(known_classes))
        X_val_eval = X_val_scaled[val_mask]
        y_val_eval = y_val[val_mask]
        y_val_encoded = label_encoder.transform(y_val_eval)

        y_pred = candidate_clf.predict(X_val_eval)

        candidate_f1 = float(f1_score(y_val_encoded, y_pred, average="macro", zero_division=0))
        candidate_prec = float(precision_score(y_val_encoded, y_pred, average="macro", zero_division=0))
        candidate_rec = float(recall_score(y_val_encoded, y_pred, average="macro", zero_division=0))

        candidate_metrics = {
            "macro_f1": candidate_f1,
            "macro_precision": candidate_prec,
            "macro_recall": candidate_rec,
            "n_classes": len(known_classes),
            "classes": list(known_classes),
        }

        # 6. Safety Gate Evaluation
        min_allowed_f1 = baseline_f1 - safety_margin
        candidate_tag = f"v{int(time.time())}.clf"

        if candidate_f1 < min_allowed_f1:
            reason = (
                f"Candidate macro F1 ({candidate_f1:.4f}) dropped below required threshold "
                f"({min_allowed_f1:.4f}) from baseline ({baseline_f1:.4f}) under {safety_margin:.2f} margin."
            )
            print(f"[Safety Gate REJECTED] {reason}")
            return RetrainResult(
                component="classifier",
                promoted=False,
                previous_version_tag=prev_version_tag,
                candidate_version_tag=candidate_tag,
                previous_metrics=prev_metrics,
                candidate_metrics=candidate_metrics,
                rejection_reason=reason,
            )

        # 7. Promotion to Production
        os.makedirs(MODELS_DIR, exist_ok=True)
        checkpoint_filename = f"classifier_{candidate_tag}.joblib"
        checkpoint_path = os.path.join(MODELS_DIR, checkpoint_filename)
        joblib.dump(candidate_clf, checkpoint_path)

        local_active_path = os.path.join(MODELS_DIR, "classifier.joblib")
        joblib.dump(candidate_clf, local_active_path)

        remote_storage_path = upload_model(
            checkpoint_path, f"classifier/{candidate_tag}/{checkpoint_filename}"
        )

        model_repository.register_model_version(
            db=db,
            component="classifier",
            version_tag=candidate_tag,
            storage_path=remote_storage_path,
            metrics=candidate_metrics,
            set_active=True,
        )

        print(f"[Safety Gate PASSED] Promoted classifier {candidate_tag} (Macro F1: {candidate_f1:.4f} >= {min_allowed_f1:.4f})")
        return RetrainResult(
            component="classifier",
            promoted=True,
            previous_version_tag=prev_version_tag,
            candidate_version_tag=candidate_tag,
            previous_metrics=prev_metrics,
            candidate_metrics=candidate_metrics,
        )

    def run_adaptation_cycle(
        self,
        db: Session,
        trigger: str = "manual",
        safety_margin: float = 0.02,
    ) -> Dict[str, Any]:
        """
        Full adaptation pipeline orchestrator:
        1. Synchronizes recent database analyst feedback into the replay buffer.
        2. Executes Autoencoder fine-tuning with safety gate.
        3. Executes Classifier fine-tuning with safety gate.
        """
        print(f"[*] Starting Sentrix Adaptation Retraining Cycle (Trigger: {trigger})...")

        # Sync feedback
        synced = self.replay_buffer.sync_database_feedback(db=db)
        print(f"[*] Synced {synced} analyst-confirmed flow samples into replay buffer.")

        # Retrain Autoencoder
        ae_res = self.retrain_autoencoder(db=db, safety_margin=0.05)

        # Retrain Classifier
        clf_res = self.retrain_classifier(db=db, safety_margin=safety_margin)

        return {
            "status": "completed",
            "trigger": trigger,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "autoencoder": ae_res.to_dict(),
            "classifier": clf_res.to_dict(),
            "any_promoted": ae_res.promoted or clf_res.promoted,
        }


_retrain_service_instance: Optional[RetrainService] = None


def get_retrain_service() -> RetrainService:
    global _retrain_service_instance
    if _retrain_service_instance is None:
        _retrain_service_instance = RetrainService()
    return _retrain_service_instance
