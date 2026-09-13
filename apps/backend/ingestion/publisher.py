import os
import sys
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.models.flow import Flow
from app.models.detection import Detection
from app.domain.detection.service import get_detection_service, DetectionResult
from app.domain.drift.service import get_drift_service
from app.domain.confidence.engine import get_confidence_engine, ConfidenceScore
from app.domain.confidence.tiers import Tier
from app.domain.containment.service import get_containment_service, ContainmentResult
from app.domain.incidents.service import get_incident_service
from app.repositories import flow_repository
from ingestion.capture import replay_dataset_csv
from ingestion.flow_features import extract_flow_features


def ingest_flow(
    flow_record: Dict[str, Any],
    db: Optional[Session] = None,
    auto_contain: bool = True,
    generate_playbook: bool = False,
) -> Dict[str, Any]:
    """
    Ingests, scores, tracks drift, computes confidence, and autonomously actuates containment.
    """
    detection_svc = get_detection_service()
    drift_svc = get_drift_service()
    confidence_engine = get_confidence_engine()
    containment_svc = get_containment_service()
    incident_svc = get_incident_service()

    # 1. Feature extraction & detection scoring
    features = extract_flow_features(flow_record)
    detection_res = detection_svc.score_flow(features)

    # 2. Concept drift observation
    drift_svc.observe(detection_res.latent_vector)
    drift_state = drift_svc.last_state
    if "drift_score" in flow_record and flow_record["drift_score"] is not None:
        current_drift_score = float(flow_record["drift_score"])
    else:
        current_drift_score = drift_state.drift_score if drift_state else 0.0

    # 3. Confidence fusion
    confidence_res: ConfidenceScore = confidence_engine.calculate(
        anomaly_score=detection_res.anomaly_score,
        classifier_margin=detection_res.classifier_margin,
        drift_score=current_drift_score,
        is_anomalous=detection_res.is_anomalous,
        db=db,
    )

    flow_obj: Optional[Flow] = None
    detection_obj: Optional[Detection] = None
    containment_res: Optional[ContainmentResult] = None
    incident_obj = None

    # 4. Database persistence and autonomous containment
    if db is not None:
        try:
            flow_obj = flow_repository.create_flow(db, flow_record)

            if detection_res.is_anomalous:
                detection_obj = Detection(
                    id=uuid.uuid4(),
                    flow_id=flow_obj.id,
                    anomaly_score=detection_res.anomaly_score,
                    is_anomalous=detection_res.is_anomalous,
                    attack_type=detection_res.attack_type,
                    classifier_margin=detection_res.classifier_margin,
                    drift_score=current_drift_score,
                    confidence_score=confidence_res.score,
                    confidence_breakdown=confidence_res.breakdown,
                )
                db.add(detection_obj)
                db.commit()
                db.refresh(detection_obj)

                # Autonomous Containment & Incident Creation for High / Medium tiers
                if auto_contain and confidence_res.tier in (Tier.HIGH, Tier.MEDIUM):
                    action_to_take = confidence_res.recommended_action
                    containment_res = containment_svc.apply_containment(
                        src_ip=flow_record["src_ip"],
                        action=action_to_take,
                    )
                    incident_obj = incident_svc.create_incident_from_detection(
                        db=db,
                        detection_id=detection_obj.id,
                        action_taken=action_to_take,
                        status="open",
                        trigger_playbook=generate_playbook,
                    )
        except Exception as e:
            print(f"Warning: Database error during flow ingestion: {e}")

    return {
        "detection": detection_res,
        "confidence": confidence_res,
        "containment": containment_res,
        "incident": incident_obj,
    }


def run_ingestion_stream(
    max_flows: int = 50,
    delay_seconds: float = 0.01,
    drift_check_interval: int = 20,
    db: Optional[Session] = None,
    auto_contain: bool = True,
) -> List[Dict[str, Any]]:
    """
    Runs live ingestion loop with continuous drift tracking, confidence calculation, and autonomous containment.
    """
    print(
        f"=== Starting Autonomous Ingestion Stream (max_flows={max_flows}, delay={delay_seconds}s) ==="
    )
    drift_svc = get_drift_service()
    results = []
    anomalies_count = 0
    contained_count = 0

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
            output = ingest_flow(flow, db=db, auto_contain=auto_contain, generate_playbook=False)
            det = output["detection"]
            conf = output["confidence"]
            contain = output.get("containment")

            if (idx + 1) % drift_check_interval == 0:
                drift_state = drift_svc.check_drift(db=db)
                print(
                    f"  [Drift Check @ flow {idx+1}] Score: {drift_state.drift_score:.4f} | "
                    f"Drifting: {drift_state.is_drifting} | Samples: {drift_state.sample_count}"
                )

            if det.is_anomalous:
                anomalies_count += 1
                contain_msg = (
                    f"ACTUATED [{contain.actuator} -> {contain.action}]"
                    if contain
                    else "MONITORED"
                )
                if contain and contain.action in ("BLOCK", "RATE_LIMIT"):
                    contained_count += 1

                print(
                    f"[THREAT DETECTED] {flow['src_ip']:<15} -> {flow['dst_ip']:<15} | "
                    f"Type: {det.attack_type:<20} | Conf: {conf.score:.2f} ({conf.tier.value}) | "
                    f"{contain_msg}"
                )

            results.append({"flow": flow, "output": output})

        print(
            f"\nIngestion stream finished: {len(results)} flows, {anomalies_count} anomalies, {contained_count} autonomous containments actuated."
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
        run_ingestion_stream(max_flows=30, delay_seconds=0.005, db=test_db)
    finally:
        test_db.close()
