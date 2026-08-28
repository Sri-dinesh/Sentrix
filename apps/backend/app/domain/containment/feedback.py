import os
import json
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.repositories import incident_repository
from app.domain.containment.service import get_containment_service

ACTIVE_LEARNING_POOL_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../../../ml/datasets/active_learning_pool.json",
    )
)


def stage_false_positive_sample(flow_dict: Dict[str, Any], label: str = "BENIGN"):
    """
    Appends a verified false positive sample into the active learning candidate pool
    for subsequent continuous retraining iterations.
    """
    os.makedirs(os.path.dirname(ACTIVE_LEARNING_POOL_FILE), exist_ok=True)
    samples: List[Dict[str, Any]] = []

    if os.path.exists(ACTIVE_LEARNING_POOL_FILE):
        try:
            with open(ACTIVE_LEARNING_POOL_FILE, "r", encoding="utf-8") as f:
                samples = json.load(f)
        except Exception:
            samples = []

    record = {
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "verified_label": label,
        "raw_features": flow_dict.get("raw_features", flow_dict),
    }
    samples.append(record)

    with open(ACTIVE_LEARNING_POOL_FILE, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)

    print(f"Staged false positive sample to active learning pool (Total: {len(samples)} samples)")


def handle_incident_resolution(
    db: Session,
    incident_id: uuid.UUID,
    new_status: str,
    resolved_by: Optional[uuid.UUID] = None,
) -> Optional[Incident]:
    """
    Processes analyst feedback on incident resolution.
    If resolved as 'false_positive':
    1. Lifts active containment across SDN/firewalls.
    2. Stages flow into active learning pool to refine anomaly boundaries.
    """
    incident = incident_repository.update_status(
        db=db,
        incident_id=incident_id,
        status=new_status,
        resolved_by=resolved_by,
    )
    if not incident:
        return None

    if new_status == "false_positive":
        detection = incident.detection
        if detection and detection.flow:
            flow = detection.flow
            src_ip = flow.src_ip

            # 1. Rollback containment
            containment_svc = get_containment_service()
            lift_res = containment_svc.lift_containment(src_ip)
            print(
                f"[Active Learning] False positive verified. Lifted containment for {src_ip}: {lift_res.action}"
            )

            # 2. Stage to retraining pool
            flow_dict = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "raw_features": flow.raw_features,
            }
            stage_false_positive_sample(flow_dict, label="BENIGN")

    return incident
