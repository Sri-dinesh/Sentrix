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
from app.domain.drift.service import get_drift_service
from app.domain.confidence.engine import get_confidence_engine, ConfidenceScore
from app.repositories import flow_repository
from ingestion.capture import replay_dataset_csv
from ingestion.flow_features import extract_flow_features


def ingest_flow(
    flow_record: Dict[str, Any],
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Ingests, scores, tracks drift, and computes calibrated confidence for a single network flow.
    """
    detection_svc = get_detection_service()
    drift_svc = get_drift_service()
    confidence_engine = get_confidence_engine()

    # 1. Feature extraction & detection scoring
    features = extract_flow_features(flow_record)
    detection_res = detection_svc.score_flow(features)

    # 2. Concept drift observation
    drift_svc.observe(detection_res.latent_vector)
    drift_state = drift_svc.last_state
    current_drift_score = drift_state.drift_score if drift_state else 0.0

    # 3. Confidence fusion
    confidence_res: ConfidenceScore = confidence_engine.calculate(
        anomaly_score=detection_res.anomaly_score,
        classifier_margin=detection_res.classifier_margin,
        drift_score=current_drift_score,
        is_anomalous=detection_res.is_anomalous,
        db=db,
    )

    # 4. Persist flow in DB if session provided
    if db is not None:
        try:
            flow_repository.create_flow(db, flow_record)
        except Exception as e:
            print(f"Warning: Failed to save flow to database: {e}")

    return {
        "detection": detection_res,
        "confidence": confidence_res,
    }


def run_ingestion_stream(
    max_flows: int = 60,
    delay_seconds: float = 0.01,
    drift_check_interval: int = 20,
    db: Optional[Session] = None,
) -> List[Dict[str, Any]]:
    """
    Runs live ingestion loop with continuous drift tracking and confidence calculation.
    """
    print(
        f"=== Starting Ingestion Pipeline (max_flows={max_flows}, delay={delay_seconds}s) ==="
    )
    drift_svc = get_drift_service()
    results = []
    anomalies_count = 0

    should_close = False
    if db is None:
        try:
            db = SessionLocal()
            should_close = True
        except Exception:
            db = None

    try:
        for idx, flow in enumerate(
            replay_dataset_csv(delay_seconds=delay_seconds, max_flows=max_flows)
        ):
            output = ingest_flow(flow, db=db)
            det = output["detection"]
            conf = output["confidence"]

            # Periodically evaluate drift window
            if (idx + 1) % drift_check_interval == 0:
                drift_state = drift_svc.check_drift(db=db)
                print(
                    f"  [Drift Check @ flow {idx+1}] Score: {drift_state.drift_score:.4f} | "
                    f"Drifting: {drift_state.is_drifting} | Samples: {drift_state.sample_count}"
                )

            if det.is_anomalous:
                anomalies_count += 1
                print(
                    f"[ALERT] {flow['src_ip']:<15} -> {flow['dst_ip']:<15} | "
                    f"Attack: {det.attack_type:<20} | Confidence: {conf.score:.2f} ({conf.tier.value}) | "
                    f"Action: {conf.recommended_action:<10} | Anomaly: {det.anomaly_score:.4f}"
                )

            results.append({"flow": flow, "output": output})

        print(
            f"\nIngestion stream completed: {len(results)} flows processed, {anomalies_count} anomalies flagged."
        )
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
        run_ingestion_stream(max_flows=40, delay_seconds=0.005, db=test_db)
    finally:
        test_db.close()
