import sys
import os
import uuid
import pytest
import joblib
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.models.base import Base
from app.models.user import User
from app.models.model_version import ModelVersion
from app.models.settings import SettingsModel
from app.db.session import get_db
from app.main import app
from app.repositories import user_repository, model_repository, settings_repository
from app.domain.adaptation.replay_buffer import ReplayBuffer, get_replay_buffer
import shutil
from app.domain.adaptation.retrain_service import RetrainService
from app.worker.tasks import run_adaptation_cycle_task

MODELS_DIR = os.path.abspath(os.path.join(backend_dir, "ml/models"))


@pytest.fixture(autouse=True)
def preserve_baseline_models():
    """Isolates production model artifacts on disk from test retraining mutations."""
    clf_path = os.path.join(MODELS_DIR, "classifier.joblib")
    ae_path = os.path.join(MODELS_DIR, "autoencoder.pt")
    clf_bak = clf_path + ".bak"
    ae_bak = ae_path + ".bak"
    if os.path.exists(clf_path):
        shutil.copy2(clf_path, clf_bak)
    if os.path.exists(ae_path):
        shutil.copy2(ae_path, ae_bak)
    yield
    if os.path.exists(clf_bak):
        shutil.copy2(clf_bak, clf_path)
        try:
            os.remove(clf_bak)
        except OSError:
            pass
    if os.path.exists(ae_bak):
        shutil.copy2(ae_bak, ae_path)
        try:
            os.remove(ae_bak)
        except OSError:
            pass


@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()

    # Seed Users
    user_repository.create_user(db, "user_analyst", "analyst@sentrix.local", role="analyst")
    user_repository.create_user(db, "user_admin", "admin@sentrix.local", role="admin")

    # Seed initial active model versions
    model_repository.register_model_version(
        db=db,
        component="autoencoder",
        version_tag="v1.0.0.ae",
        storage_path="models/autoencoder.pt",
        metrics={"best_val_loss": 0.015, "anomaly_threshold": 0.05},
        set_active=True,
    )

    model_repository.register_model_version(
        db=db,
        component="classifier",
        version_tag="v1.0.0.clf",
        storage_path="models/classifier.joblib",
        metrics={"macro_f1": 0.83, "macro_precision": 0.84, "macro_recall": 0.85},
        set_active=True,
    )

    # Seed settings
    settings_repository.get_settings(db)

    db.commit()
    yield db
    db.close()


def test_replay_buffer_sampling():
    """Verifies ReplayBuffer returns correctly proportioned batches and handles edge cases."""
    buffer = ReplayBuffer(max_buffer_size=1000, replay_ratio=0.70)
    
    # 1. Add synthetic live sample
    dummy_features = {"Destination Port": 80, "Flow Duration": 120000, "SYN Flag Count": 1}
    buffer.add_sample(dummy_features, label="BENIGN", persist=False)

    # 2. Sample general batch
    batch_size = 100
    X_batch, y_batch = buffer.get_training_batch(size=batch_size, replay_ratio=0.70)
    assert len(X_batch) == batch_size
    assert len(y_batch) == batch_size
    assert X_batch.shape[1] > 10, "Should have full feature dimension"

    # 3. Sample benign-only batch
    X_benign, y_benign = buffer.get_training_batch(size=50, benign_only=True)
    assert len(X_benign) == 50
    assert all(label.upper() == "BENIGN" for label in y_benign)


def test_retrain_service_promotion_on_valid_data(test_db):
    """
    Tests that fine-tuning with valid, improving replay data satisfies
    the safety gates and successfully promotes a new active model version.
    """
    service = RetrainService()

    # 1. Test Autoencoder Fine-Tuning
    ae_res = service.retrain_autoencoder(
        db=test_db,
        epochs=1,
        lr=1e-4,
        safety_margin=0.50,  # Generous margin to test promotion path
        training_batch_size=100,
    )

    assert ae_res.promoted is True, f"Autoencoder should be promoted: {ae_res.rejection_reason}"
    assert ae_res.component == "autoencoder"

    # Verify active model in DB was updated
    active_ae = model_repository.get_active_model(test_db, "autoencoder")
    assert active_ae is not None
    assert active_ae.version_tag == ae_res.candidate_version_tag

    # 2. Test Classifier Fine-Tuning
    clf_res = service.retrain_classifier(
        db=test_db,
        safety_margin=0.50,
        training_batch_size=200,
    )

    assert clf_res.promoted is True, f"Classifier should be promoted: {clf_res.rejection_reason}"
    assert clf_res.component == "classifier"

    active_clf = model_repository.get_active_model(test_db, "classifier")
    assert active_clf is not None
    assert active_clf.version_tag == clf_res.candidate_version_tag


def test_retrain_service_safety_gate_rejection(test_db):
    """
    Tests that corrupted / adversarial batches causing regression are strictly
    BLOCKED by the safety gates and the active model version is NOT replaced.
    """
    service = RetrainService()
    initial_active_clf = model_repository.get_active_model(test_db, "classifier")
    initial_version_tag = initial_active_clf.version_tag

    # 1. Deliberately construct corrupted / noise batch
    n_samples = 200
    dim = service._get_scaler().n_features_in_
    # Extreme noise features that destroy decision boundaries
    corrupted_X = np.random.uniform(-1000.0, 1000.0, size=(n_samples, dim)).astype(np.float32)
    # Uniformly random labels across known classes
    label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.joblib"))
    corrupted_y = np.random.choice(label_encoder.classes_, size=n_samples)

    # 2. Execute classifier retraining with strict safety margin (0.01)
    res = service.retrain_classifier(
        db=test_db,
        safety_margin=0.01,
        custom_batch=(corrupted_X, corrupted_y),
    )

    # 3. Assert safety gate REJECTED the degraded candidate
    assert res.promoted is False, "Safety gate must reject degraded candidate!"
    assert res.rejection_reason is not None
    assert "dropped below" in res.rejection_reason or "exceeded" in res.rejection_reason

    # 4. Verify existing active model remains in production
    current_active_clf = model_repository.get_active_model(test_db, "classifier")
    assert current_active_clf.version_tag == initial_version_tag, "Active model must remain untouched on regression!"


def test_celery_task_adaptation_execution(test_db, monkeypatch):
    """Verifies that the Celery task runs the adaptation cycle and handles execution."""
    # Monkeypatch SessionLocal in tasks module to use our in-memory test_db
    monkeypatch.setattr("app.worker.tasks.SessionLocal", lambda: test_db)

    # Execute task synchronously
    result = run_adaptation_cycle_task(trigger="test_unit", requested_by="admin_test", safety_margin=0.50)
    assert result["status"] == "success"
    assert result["trigger"] == "test_unit"
    assert "results" in result


def test_retrain_api_endpoint_rbac(test_db):
    """Tests that POST /api/v1/settings/retrain requires admin role privileges."""
    from app.api.deps import get_current_user

    client = TestClient(app)

    # Mock DB dependency
    app.dependency_overrides[get_db] = lambda: test_db

    try:
        # 1. Analyst user attempt -> 403 Forbidden
        analyst_user = User(id=uuid.uuid4(), email="analyst@sentrix.local", role="analyst")
        app.dependency_overrides[get_current_user] = lambda: analyst_user

        res = client.post("/api/v1/settings/retrain", json={"safety_margin": 0.02})
        assert res.status_code == 403, f"Analyst should get 403 Forbidden, got {res.status_code}"

        # 2. Admin user attempt -> 202 Accepted
        admin_user = User(id=uuid.uuid4(), email="admin@sentrix.local", role="admin")
        app.dependency_overrides[get_current_user] = lambda: admin_user

        res = client.post("/api/v1/settings/retrain", json={"safety_margin": 0.02})
        assert res.status_code == 202, f"Admin should get 202 Accepted, got {res.status_code}"
        data = res.json()
        assert data["status"] == "queued"
        assert "task_id" in data
        assert data["safety_margin"] == 0.02
    finally:
        app.dependency_overrides.clear()
