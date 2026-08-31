import sys
import os
import uuid
import pytest
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
from app.models.mitre import MitreTechnique
from app.models.model_version import ModelVersion
from app.db.session import get_db
from app.main import app
from app.repositories import user_repository, incident_repository
from app.domain.containment.service import get_containment_service
from app.domain.containment.feedback import handle_incident_resolution, ACTIVE_LEARNING_POOL_FILE
from ingestion.publisher import ingest_flow


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

    # Seed MITRE techniques
    techniques = [
        MitreTechnique(id="T1498", name="Network Denial of Service", tactic="Impact", description="DoS attack"),
        MitreTechnique(id="T1110", name="Brute Force", tactic="Credential Access", description="Brute force credentials"),
        MitreTechnique(id="T1595.001", name="Port Scanning", tactic="Reconnaissance", description="Port scanning"),
        MitreTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access", description="Web application exploit"),
    ]
    for t in techniques:
        db.add(t)

    # Seed Users
    user_repository.create_user(db, "user_analyst", "analyst@sentrix.local", role="analyst")
    user_repository.create_user(db, "user_admin", "admin@sentrix.local", role="admin")

    db.commit()
    yield db
    db.close()


def test_full_end_to_end_soc_pipeline(test_db):
    """
    Comprehensive End-to-End SOC Lifecycle Test:
    1. Ingests malicious attack flow
    2. Autoencoder flags anomaly & classifier identifies attack label
    3. Multi-signal confidence classifies response tier
    4. Autonomous containment blocks source IP
    5. Incident created and linked to MITRE technique
    6. AI Playbook synthesized
    7. REST API retrieves incident forensics
    8. Analyst resolves as False Positive -> verifies containment is lifted and staged for retraining
    """
    # 1. Ingest malicious flow trace
    malicious_flow = {
        "src_ip": "198.51.100.44",
        "dst_ip": "192.168.10.50",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 850,
        "byte_count": 124000,
        "duration": 0.45,
        "raw_features": {
            "Destination Port": 80,
            "Flow Duration": 450000,
            "Total Fwd Packets": 450,
            "Total Backward Packets": 400,
            "Total Length of Fwd Packets": 64000,
            "Total Length of Bwd Packets": 60000,
            "Flow Bytes/s": 275555.5,
            "Flow Packets/s": 1888.8,
            "SYN Flag Count": 1,
            "ACK Flag Count": 1,
        },
    }

    result = ingest_flow(malicious_flow, db=test_db, auto_contain=True, generate_playbook=True)

    det = result["detection"]
    conf = result["confidence"]
    contain = result["containment"]
    incident = result["incident"]

    assert det.is_anomalous is True, "Flow should be detected as anomalous"
    assert det.anomaly_score > 0.026147, "Anomaly score must exceed calibrated threshold"
    assert conf.score >= 0.50, "Confidence score must reflect detected threat"
    assert contain is not None, "Containment result must be generated"
    assert contain.success is True, "Containment actuation must succeed"
    assert incident is not None, "Security incident must be created"
    assert incident.mitre_technique_id in ("T1498", "T1190", "T1110", "T1595.001"), "Incident must map to a valid MITRE technique"

    # Verify containment driver state
    containment_svc = get_containment_service()
    assert "198.51.100.44" in containment_svc.list_active_contained_ips()

    # 2. Query Incident via FastAPI REST API Client
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    auth_headers = {"Authorization": "Bearer test_token_user_analyst"}
    api_res = client.get(f"/api/v1/incidents/{incident.id}", headers=auth_headers)
    assert api_res.status_code == 200
    incident_json = api_res.json()
    assert incident_json["mitre_technique"]["id"] == incident.mitre_technique_id
    assert incident_json["flow"]["src_ip"] == "198.51.100.44"
    assert incident_json["playbook"] is not None
    assert len(incident_json["playbook"]["content"]) > 50

    # 3. Analyst reviews and marks as False Positive
    patch_res = client.patch(
        f"/api/v1/incidents/{incident.id}/status",
        json={"status": "false_positive"},
        headers=auth_headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "false_positive"

    # 4. Verify Active Learning & Containment Rollback
    assert "198.51.100.44" not in containment_svc.list_active_contained_ips(), "Containment must be lifted"
    assert os.path.exists(ACTIVE_LEARNING_POOL_FILE), "Active learning pool file must exist"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
