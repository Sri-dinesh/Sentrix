import os
import sys
import json
from typing import Optional
from sqlalchemy.orm import Session

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.core.storage import upload_model
from app.repositories import model_repository

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
AUTOENCODER_PATH = os.path.join(MODELS_DIR, "autoencoder.pt")
AE_META_PATH = os.path.join(MODELS_DIR, "autoencoder_meta.json")
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "classifier.joblib")
CLASSIFIER_META_PATH = os.path.join(MODELS_DIR, "classifier_meta.json")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")


def register_offline_models(
    version_tag: str = "v1.0.0",
    db: Optional[Session] = None,
):
    print(f"=== Registering Model Checkpoints ({version_tag}) ===")

    if not os.path.exists(AUTOENCODER_PATH) or not os.path.exists(CLASSIFIER_PATH):
        raise FileNotFoundError(
            "Trained checkpoints not found in ml/models/. Run train_autoencoder.py and train_classifier.py first."
        )

    # 1. Upload checkpoints to storage
    print("Uploading models to checkpoint storage...")
    ae_remote = upload_model(
        AUTOENCODER_PATH, f"autoencoder/{version_tag}/autoencoder.pt"
    )
    clf_remote = upload_model(
        CLASSIFIER_PATH, f"classifier/{version_tag}/classifier.joblib"
    )
    scaler_remote = upload_model(
        SCALER_PATH, f"scaler/{version_tag}/scaler.joblib"
    )

    # 2. Load metrics metadata
    with open(AE_META_PATH, "r", encoding="utf-8") as f:
        ae_meta = json.load(f)

    with open(CLASSIFIER_META_PATH, "r", encoding="utf-8") as f:
        clf_meta = json.load(f)

    # 3. Register in Database
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        # Register Autoencoder
        ae_record = model_repository.register_model_version(
            db=db,
            component="autoencoder",
            version_tag=version_tag,
            storage_path=ae_remote,
            metrics={
                "anomaly_threshold": ae_meta.get("anomaly_threshold"),
                "mean_error": ae_meta.get("mean_error"),
                "best_val_loss": ae_meta.get("best_val_loss"),
                "input_dim": ae_meta.get("input_dim"),
                "latent_dim": ae_meta.get("latent_dim"),
            },
            set_active=True,
        )
        print(
            f"Registered Active Autoencoder: ID={ae_record.id}, Version={ae_record.version_tag}, Path={ae_record.storage_path}"
        )

        # Register Classifier
        clf_record = model_repository.register_model_version(
            db=db,
            component="classifier",
            version_tag=version_tag,
            storage_path=clf_remote,
            metrics={
                "macro_f1": clf_meta.get("macro_f1"),
                "macro_precision": clf_meta.get("macro_precision"),
                "macro_recall": clf_meta.get("macro_recall"),
                "mean_margin": clf_meta.get("mean_margin"),
                "n_classes": clf_meta.get("n_classes"),
                "classes": clf_meta.get("classes"),
            },
            set_active=True,
        )
        print(
            f"Registered Active Classifier: ID={clf_record.id}, Version={clf_record.version_tag}, Path={clf_record.storage_path}"
        )

        print(
            "\nAll initial models successfully registered into model_versions table!"
        )
        return ae_record, clf_record
    except Exception as e:
        db.rollback()
        print(f"Failed to register models in database: {e}")
        raise
    finally:
        if should_close:
            db.close()


if __name__ == "__main__":
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    test_db = TestSession()
    try:
        register_offline_models("v1.0.0", db=test_db)
    finally:
        test_db.close()
