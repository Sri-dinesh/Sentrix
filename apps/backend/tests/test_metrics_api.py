import sys
import os
import uuid
from datetime import datetime, timezone, timedelta
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
from app.models.flow import Flow
from app.models.detection import Detection
from app.models.incident import Incident
from app.db.session import get_db
from app.main import app
from app.api.deps import get_current_user
from app.repositories import user_repository, metrics_repository


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

    # Seed User
    user_repository.create_user(db, "user_analyst", "analyst@sentrix.local", role="analyst")

    db.commit()
    yield db
    db.close()


def test_mttd_and_mttr_calculations(test_db):
    """Tests SQL aggregate calculations for MTTD and MTTR."""
    now = datetime.now(timezone.utc)

    # Initially empty DB -> 0.0 latency, 0 counts
    mttd_empty = metrics_repository.compute_mttd(test_db, window_hours=24)
    assert mttd_empty["mean_seconds"] == 0.0
    assert mttd_empty["sample_count"] == 0

    mttr_empty = metrics_repository.compute_mttr(test_db, window_hours=24)
    assert mttr_empty["mean_seconds"] == 0.0
    assert mttr_empty["resolved_count"] == 0

    # Populate sample flow, detection, and resolved incident
    flow_time = now - timedelta(seconds=12)
    det_time = now - timedelta(seconds=10)   # Detection took 2 seconds
    inc_created = now - timedelta(seconds=8)
    inc_resolved = now - timedelta(seconds=2) # Remediation took 6 seconds

    flow = Flow(
        id=uuid.uuid4(),
        captured_at=flow_time,
        src_ip="10.0.0.45",
        dst_ip="192.168.1.10",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        duration=0.5,
    )
    test_db.add(flow)
    test_db.flush()

    detection = Detection(
        id=uuid.uuid4(),
        flow_id=flow.id,
        anomaly_score=0.45,
        is_anomalous=True,
        confidence_score=0.92,
        detected_at=det_time,
    )
    test_db.add(detection)
    test_db.flush()

    incident = Incident(
        id=uuid.uuid4(),
        detection_id=detection.id,
        status="resolved",
        action_taken="BLOCK",
        created_at=inc_created,
        resolved_at=inc_resolved,
    )
    test_db.add(incident)
    test_db.commit()

    # Verify calculated aggregates
    mttd_data = metrics_repository.compute_mttd(test_db, window_hours=24)
    assert mttd_data["sample_count"] == 1
    assert 1.9 <= mttd_data["mean_seconds"] <= 2.1

    mttr_data = metrics_repository.compute_mttr(test_db, window_hours=24)
    assert mttr_data["resolved_count"] == 1
    assert 5.9 <= mttr_data["mean_seconds"] <= 6.1


def test_metrics_api_endpoints(test_db):
    """Tests FastAPI /api/v1/metrics endpoints with dependency overrides."""
    client = TestClient(app)

    # Seed mock user
    analyst_user = User(id=uuid.uuid4(), email="analyst@sentrix.local", role="analyst")
    app.dependency_overrides[get_current_user] = lambda: analyst_user
    app.dependency_overrides[get_db] = lambda: test_db

    try:
        # 1. GET /api/v1/metrics/mttd
        res_mttd = client.get("/api/v1/metrics/mttd?window_hours=12")
        assert res_mttd.status_code == 200
        data_mttd = res_mttd.json()
        assert "mean_seconds" in data_mttd
        assert data_mttd["window_hours"] == 12

        # 2. GET /api/v1/metrics/mttr
        res_mttr = client.get("/api/v1/metrics/mttr")
        assert res_mttr.status_code == 200
        data_mttr = res_mttr.json()
        assert "mean_seconds" in data_mttr

        # 3. GET /api/v1/metrics/overview
        res_overview = client.get("/api/v1/metrics/overview")
        assert res_overview.status_code == 200
        data_overview = res_overview.json()
        assert "mttd" in data_overview
        assert "mttr" in data_overview
        assert "total_incidents" in data_overview
        assert "incidents_by_status" in data_overview
        assert "incidents_by_tier" in data_overview
        assert "active_containment_blocks" in data_overview
        assert "concept_drift_score" in data_overview
    finally:
        app.dependency_overrides.clear()
