import os
import sys
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.domain.detection.service import get_detection_service, DetectionResult
from app.repositories import flow_repository
from ingestion.capture import replay_dataset_csv
from ingestion.flow_features import extract_flow_features


def ingest_flow(
    flow_record: Dict[str, Any],
    db: Optional[Session] = None,
) -> DetectionResult:
    """
    Ingests and scores an individual network flow record.
    Extracts features, runs detection service, and records flow in DB.
    """
    detection_svc = get_detection_service()
    features = extract_flow_features(flow_record)
    result = detection_svc.score_flow(features)

    # Persist flow if DB session provided
    if db is not None:
        try:
            flow_repository.create_flow(db, flow_record)
        except Exception as e:
            print(f"Warning: Failed to save flow to database: {e}")

    return result


def run_ingestion_stream(
    max_flows: int = 50,
    delay_seconds: float = 0.05,
    db: Optional[Session] = None,
) -> List[Dict[str, Any]]:
    """
    Runs live ingestion loop across max_flows.
    """
    print(f"=== Starting Ingestion Pipeline (max_flows={max_flows}, delay={delay_seconds}s) ===")
    results = []
    anomalies_detected = 0

    should_close = False
    if db is None:
        try:
            db = SessionLocal()
            should_close = True
        except Exception:
            db = None

    try:
        for flow in replay_dataset_csv(delay_seconds=delay_seconds, max_flows=max_flows):
            res = ingest_flow(flow, db=db)
            if res.is_anomalous:
                anomalies_detected += 1
                print(
                    f"[ANOMALY FLAGGED] Source: {flow['src_ip']:<15} -> {flow['dst_ip']:<15} | "
                    f"Attack: {res.attack_type:<25} | Anomaly Score: {res.anomaly_score:.5f} | "
                    f"Margin: {res.classifier_margin:.3f} | Actual: {flow['actual_label']}"
                )
            results.append({"flow": flow, "result": res})

        print(f"\nIngestion stream finished: {len(results)} flows processed, {anomalies_detected} anomalies detected.")
        return results
    finally:
        if should_close and db is not None:
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
        run_ingestion_stream(max_flows=25, delay_seconds=0.01, db=test_db)
    finally:
        test_db.close()
