import os
import sys
import uuid
import math
import joblib
import pytest
import numpy as np
import httpx
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import shutil
from app.models.base import Base
from app.models.flow import Flow
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.mitre import MitreTechnique
from app.models.model_version import ModelVersion
from app.domain.containment.service import ContainmentService, get_containment_service
from app.domain.containment.ryu_client import RyuSDNClient
from app.domain.containment.iptables_driver import IptablesDriver
from app.domain.playbooks.service import PlaybookService
from app.domain.adaptation.retrain_service import RetrainService
from app.repositories import model_repository
from app.core.llm import OllamaClient
from ingestion.publisher import ingest_flow
from ingestion.flow_features import extract_flow_features, get_feature_columns

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
        os.remove(clf_bak)
    if os.path.exists(ae_bak):
        shutil.copy2(ae_bak, ae_path)
        os.remove(ae_bak)


@pytest.fixture
def failover_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()

    # Seed MITRE techniques
    techniques = [
        MitreTechnique(id="T1498", name="Network Denial of Service", tactic="Impact", description="DoS attack"),
        MitreTechnique(id="T1110", name="Brute Force", tactic="Credential Access", description="Brute force credentials"),
        MitreTechnique(id="T1595.001", name="Port Scanning", tactic="Reconnaissance", description="Port scanning"),
        MitreTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access", description="Web application exploit"),
    ]
    for t in techniques:
        db.add(t)
    db.commit()

    yield db
    db.close()


def test_failure_mode_ryu_controller_unreachable():
    """
    Failure Mode 1: Ryu OpenFlow SDN Controller is unreachable (connection refused/timeout).
    Expected Behavior: ContainmentService automatically falls back to host iptables driver,
    applies the block, returns success=True with actuator='IPTABLES', and safely lifts containment.
    """
    # Create Ryu client pointing to non-existent port
    dead_ryu = RyuSDNClient(base_url="http://127.0.0.1:59999", timeout_seconds=0.1)
    host_driver = IptablesDriver()
    containment_svc = ContainmentService(ryu_client=dead_ryu, iptables_driver=host_driver)

    assert dead_ryu.is_controller_available() is False, "Dead controller must report unavailable"

    test_ip = "198.51.100.222"

    # Apply containment under dead SDN controller
    result = containment_svc.apply_containment(src_ip=test_ip, action="BLOCK")

    assert result is not None
    assert result.success is True, "Fallback containment must succeed"
    assert result.actuator == "IPTABLES", "Actuator must degrade to IPTABLES"
    assert test_ip in containment_svc.list_active_contained_ips()
    assert host_driver.is_ip_blocked(test_ip) is True

    # Lift containment when SDN controller is still dead
    lift_res = containment_svc.lift_containment(src_ip=test_ip)
    assert lift_res.success is True
    assert test_ip not in containment_svc.list_active_contained_ips()
    assert host_driver.is_ip_blocked(test_ip) is False


def test_failure_mode_ollama_service_offline(failover_db):
    """
    Failure Mode 2: Local Ollama LLM daemon is offline or returning HTTP errors.
    Expected Behavior: PlaybookService falls back to deterministic template synthesis,
    persisting a structured incident response playbook without failing the request.
    """
    # Create incident in database
    flow = Flow(
        id=uuid.uuid4(),
        src_ip="203.0.113.88",
        dst_ip="10.0.0.10",
        src_port=44444,
        dst_port=80,
        protocol="TCP",
        packet_count=100,
        byte_count=10000,
        duration=0.5,
    )
    failover_db.add(flow)
    failover_db.flush()

    detection = Detection(
        id=uuid.uuid4(),
        flow_id=flow.id,
        anomaly_score=0.45,
        is_anomalous=True,
        attack_type="DoS Hulk",
        classifier_margin=0.92,
        drift_score=0.0,
        confidence_score=0.88,
        confidence_breakdown={"status": "elevated"},
    )
    failover_db.add(detection)
    failover_db.flush()

    incident = Incident(
        id=uuid.uuid4(),
        detection_id=detection.id,
        mitre_technique_id="T1498",
        status="open",
        action_taken="BLOCK",
    )
    failover_db.add(incident)
    failover_db.commit()

    # Configure PlaybookService with dead Ollama client
    offline_ollama = OllamaClient(base_url="http://127.0.0.1:59999", timeout_seconds=0.1)
    playbook_svc = PlaybookService()
    playbook_svc.llm_client = offline_ollama

    # Execute playbook generation against dead LLM service
    playbook = playbook_svc.generate_playbook_for_incident(
        db=failover_db,
        incident_id=incident.id,
    )

    assert playbook is not None, "Fallback playbook must be created"
    assert playbook.incident_id == incident.id
    assert "## 1. Executive Summary" in playbook.content
    assert "## 3. Immediate Containment Actions" in playbook.content
    assert "iptables" in playbook.content.lower()


def test_failure_mode_corrupt_and_malformed_flow_telemetry(failover_db):
    """
    Failure Mode 3: Malformed network flows with extreme values, NaNs, infinities,
    and missing dictionary fields processed through the live ingestion pipeline.
    Expected Behavior: Pipeline sanitizes inputs via extract_flow_features, zero-imputes,
    and executes without unhandled exceptions or crashes.
    """
    corrupt_flows = [
        # 1. Completely empty dictionary
        {},
        # 2. NaNs across all telemetry fields
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": float("nan"),
            "dst_port": float("nan"),
            "packet_count": float("nan"),
            "byte_count": float("nan"),
            "duration": float("nan"),
            "raw_features": {col: float("nan") for col in get_feature_columns()},
        },
        # 3. Positive and negative infinities
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 80,
            "dst_port": 8080,
            "raw_features": {
                "Flow Duration": float("inf"),
                "Flow Bytes/s": float("-inf"),
                "Packet Length Mean": 1e30,
                "Total Fwd Packets": -99999,
            },
        },
        # 4. Incompatible string types in numeric fields
        {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "src_port": "INVALID_PORT",
            "protocol": 12345,
            "raw_features": {
                "Destination Port": "NOT_A_NUMBER",
                "Flow Duration": None,
                "Total Fwd Packets": ["ARRAY_NOT_ALLOWED"],
            },
        },
    ]

    for flow_input in corrupt_flows:
        # Verify feature extraction is safe
        features = extract_flow_features(flow_input)
        assert isinstance(features, np.ndarray)
        assert features.shape == (71,)
        assert not np.isnan(features).any(), "Sanitized features must contain no NaNs"
        assert not np.isinf(features).any(), "Sanitized features must contain no Infs"

        # Verify live ingestion does not crash
        result = ingest_flow(
            flow_input,
            db=failover_db,
            auto_contain=True,
            generate_playbook=False,
        )
        assert result is not None
        assert "detection" in result
        assert "confidence" in result
        assert not math.isnan(result["confidence"].score)


def test_failure_mode_adaptation_safety_gate_rejection(failover_db):
    """
    Failure Mode 4: Model fine-tuning / adaptation on corrupted or adversarial data
    causes performance degradation.
    Expected Behavior: Safety evaluation gate detects drop in macro F1,
    rejects candidate promotion, logs rejection diagnostics, and preserves baseline model on disk.
    """
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../ml/models"))
    classifier_path = os.path.join(models_dir, "classifier.joblib")

    service = RetrainService()

    # Seed an active model in database
    model_repository.register_model_version(
        db=failover_db,
        component="classifier",
        version_tag="v1.0.0-baseline",
        storage_path="models/classifier.joblib",
        metrics={"macro_f1": 0.88, "macro_precision": 0.89, "macro_recall": 0.87},
        set_active=True,
    )

    # Construct deliberately corrupted batch with extreme noise that degrades decision boundaries
    n_samples = 150
    dim = service._get_scaler().n_features_in_
    corrupted_X = np.random.uniform(-1000.0, 1000.0, size=(n_samples, dim)).astype(np.float32)
    label_encoder = joblib.load(os.path.join(models_dir, "label_encoder.joblib"))
    corrupted_y = np.random.choice(label_encoder.classes_, size=n_samples)

    # Retrain with strict safety margin
    res = service.retrain_classifier(
        db=failover_db,
        safety_margin=0.01,
        custom_batch=(corrupted_X, corrupted_y),
    )

    assert res.promoted is False, "Degraded candidate must be rejected by safety gate"
    assert res.rejection_reason is not None
    assert "dropped below" in res.rejection_reason or "exceeded" in res.rejection_reason

    # Verify active model remains the baseline
    active_clf = model_repository.get_active_model(failover_db, "classifier")
    assert active_clf.version_tag == "v1.0.0-baseline", "Active model must remain untouched on regression"


def test_failure_mode_database_temporary_disconnect_in_stream():
    """
    Failure Mode 5: Database is completely unreachable during high-throughput flow ingestion.
    Expected Behavior: Ingestion pipeline continues real-time threat evaluation in memory,
    returning detection scores, confidence tiering, and containment actuation without crashing.
    """
    valid_flow = {
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 1500,
        "duration": 0.05,
        "raw_features": {
            "Destination Port": 443,
            "Flow Duration": 50000,
            "Total Fwd Packets": 5,
            "Total Backward Packets": 5,
        },
    }

    # Ingestion with db=None (simulating disconnected DB pool)
    result = ingest_flow(
        valid_flow,
        db=None,
        auto_contain=True,
        generate_playbook=False,
    )

    assert result is not None
    assert result["detection"] is not None
    assert result["confidence"] is not None
    assert isinstance(result["confidence"].score, float)
    assert result["confidence"].tier in ("HIGH", "MEDIUM", "LOW")
