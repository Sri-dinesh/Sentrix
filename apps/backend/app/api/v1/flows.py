import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.flow import Flow
from app.models.detection import Detection
from app.domain.detection.service import get_detection_service
from app.domain.drift.service import get_drift_service
from app.domain.confidence.engine import get_confidence_engine
from app.repositories import flow_repository
from ingestion.flow_features import extract_flow_features

router = APIRouter(prefix="/flows", tags=["flows"])


class ScoreFlowRequest(BaseModel):
    src_ip: str = "10.0.0.10"
    dst_ip: str = "192.168.1.50"
    src_port: int = 49152
    dst_port: int = 80
    protocol: str = "TCP"
    packet_count: int = 10
    byte_count: int = 1500
    duration: float = 0.5
    raw_features: Optional[Dict[str, Any]] = None


@router.post("/score", summary="Score a network flow")
def score_flow_endpoint(
    req: ScoreFlowRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Evaluates a flow feature vector through the Autoencoder and Classifier,
    computing the multi-signal confidence score and response tier.
    """
    flow_dict = req.model_dump()
    features = extract_flow_features(flow_dict)

    detection_svc = get_detection_service()
    drift_svc = get_drift_service()
    confidence_engine = get_confidence_engine()

    detection_res = detection_svc.score_flow(features)
    drift_state = drift_svc.last_state
    current_drift_score = drift_state.drift_score if drift_state else 0.0

    confidence_res = confidence_engine.calculate(
        anomaly_score=detection_res.anomaly_score,
        classifier_margin=detection_res.classifier_margin,
        drift_score=current_drift_score,
        is_anomalous=detection_res.is_anomalous,
        db=db,
    )

    return {
        "flow": flow_dict,
        "detection": detection_res.to_dict(),
        "confidence": confidence_res.to_dict(),
    }


@router.get("", summary="Search and list network flows")
def list_flows_endpoint(
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    date_from: Optional[datetime] = Query(None, description="Start timestamp"),
    date_to: Optional[datetime] = Query(None, description="End timestamp"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves a paginated list of network flow records with multi-criteria forensic filtering.
    """
    flows, total = flow_repository.search_flows(
        db=db,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": str(f.id),
                "captured_at": f.captured_at.isoformat() if f.captured_at else None,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
                "duration": f.duration,
            }
            for f in flows
        ],
    }


@router.get("/detections/recent", summary="List recent detections")
def list_recent_detections_endpoint(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Lists recent detections with confidence scores and breakdown details.
    """
    detections = (
        db.query(Detection)
        .order_by(Detection.detected_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(detections),
        "items": [
            {
                "id": str(d.id),
                "flow_id": str(d.flow_id),
                "detected_at": d.detected_at.isoformat() if d.detected_at else None,
                "anomaly_score": d.anomaly_score,
                "is_anomalous": d.is_anomalous,
                "attack_type": d.attack_type,
                "classifier_margin": d.classifier_margin,
                "drift_score": d.drift_score,
                "confidence_score": d.confidence_score,
                "confidence_breakdown": d.confidence_breakdown,
                "flow": {
                    "src_ip": d.flow.src_ip if d.flow else None,
                    "dst_ip": d.flow.dst_ip if d.flow else None,
                    "src_port": d.flow.src_port if d.flow else None,
                    "dst_port": d.flow.dst_port if d.flow else None,
                    "protocol": d.flow.protocol if d.flow else None,
                }
                if d.flow
                else None,
            }
            for d in detections
        ],
    }


@router.get("/{flow_id}", summary="Get flow by ID")
def get_flow_by_id_endpoint(
    flow_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves full raw telemetry and metadata for a specific network flow.
    """
    flow = flow_repository.get_by_id(db, flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow {flow_id} not found.",
        )

    return {
        "id": str(flow.id),
        "captured_at": flow.captured_at.isoformat() if flow.captured_at else None,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "duration": flow.duration,
        "raw_features": flow.raw_features,
    }
