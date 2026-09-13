from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.incident import Incident
from app.models.detection import Detection
from app.models.flow import Flow
from app.domain.containment.service import get_containment_service
from app.domain.drift.service import get_drift_service


def compute_mttd(db: Session, window_hours: int = 24) -> Dict[str, Any]:
    """
    Computes Mean Time to Detect (MTTD) in seconds:
    Average latency between flow packet capture (Flow.captured_at) and anomaly detection (Detection.detected_at).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    
    # Check SQL dialect for cross-compatibility (SQLite in tests, PostgreSQL in production)
    is_sqlite = db.bind is not None and db.bind.dialect.name == "sqlite"
    if is_sqlite:
        diff_expr = (func.julianday(Detection.detected_at) - func.julianday(Flow.captured_at)) * 86400.0
    else:
        diff_expr = func.extract("epoch", Detection.detected_at - Flow.captured_at)

    result = (
        db.query(
            func.avg(diff_expr).label("avg_diff"),
            func.count(Detection.id).label("count"),
        )
        .join(Flow, Detection.flow_id == Flow.id)
        .filter(Detection.detected_at >= cutoff)
        .first()
    )

    avg_seconds = float(result.avg_diff) if result and result.avg_diff is not None else 0.0
    # Ensure positive value
    avg_seconds = max(0.0, avg_seconds)
    sample_count = int(result.count) if result and result.count is not None else 0

    return {
        "mean_seconds": round(avg_seconds, 3),
        "sample_count": sample_count,
        "window_hours": window_hours,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def compute_mttr(db: Session, window_hours: int = 24) -> Dict[str, Any]:
    """
    Computes Mean Time to Remediate / Respond (MTTR) in seconds:
    Average latency between incident creation (Incident.created_at) and resolution (Incident.resolved_at).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    is_sqlite = db.bind is not None and db.bind.dialect.name == "sqlite"
    if is_sqlite:
        diff_expr = (func.julianday(Incident.resolved_at) - func.julianday(Incident.created_at)) * 86400.0
    else:
        diff_expr = func.extract("epoch", Incident.resolved_at - Incident.created_at)

    result = (
        db.query(
            func.avg(diff_expr).label("avg_diff"),
            func.count(Incident.id).label("count"),
        )
        .filter(
            Incident.resolved_at.isnot(None),
            Incident.resolved_at >= cutoff,
        )
        .first()
    )

    avg_seconds = float(result.avg_diff) if result and result.avg_diff is not None else 0.0
    avg_seconds = max(0.0, avg_seconds)
    resolved_count = int(result.count) if result and result.count is not None else 0

    return {
        "mean_seconds": round(avg_seconds, 3),
        "resolved_count": resolved_count,
        "window_hours": window_hours,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_metrics_overview(db: Session) -> Dict[str, Any]:
    """
    Aggregates comprehensive executive SOC telemetry:
    - MTTD and MTTR latencies
    - Incident status distributions
    - Confidence tier distributions
    - Active line-rate containment rules
    - Concept drift status
    """
    mttd_data = compute_mttd(db, window_hours=24)
    mttr_data = compute_mttr(db, window_hours=24)

    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    total_contained = (
        db.query(func.count(Incident.id))
        .filter(Incident.action_taken.in_(["BLOCK", "RATE_LIMIT"]))
        .scalar()
        or 0
    )

    # Status distribution
    status_counts = (
        db.query(Incident.status, func.count(Incident.id))
        .group_by(Incident.status)
        .all()
    )
    status_map: Dict[str, int] = {
        "open": 0,
        "investigating": 0,
        "contained": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    for stat, cnt in status_counts:
        status_map[stat] = cnt

    # Tier breakdown based on confidence score calibration
    high_tier_count = (
        db.query(func.count(Incident.id))
        .join(Detection, Incident.detection_id == Detection.id)
        .filter(Detection.confidence_score >= 0.85)
        .scalar()
        or 0
    )
    med_tier_count = (
        db.query(func.count(Incident.id))
        .join(Detection, Incident.detection_id == Detection.id)
        .filter(Detection.confidence_score >= 0.50, Detection.confidence_score < 0.85)
        .scalar()
        or 0
    )
    low_tier_count = (
        db.query(func.count(Incident.id))
        .join(Detection, Incident.detection_id == Detection.id)
        .filter(Detection.confidence_score < 0.50)
        .scalar()
        or 0
    )

    # Active containment blocks
    containment_svc = get_containment_service()
    active_blocks = len(containment_svc.list_active_contained_ips())

    # Concept drift status
    drift_svc = get_drift_service()
    drift_state = drift_svc.check_drift(db=None)

    total_flows = db.query(func.count(Flow.id)).scalar() or 0

    return {
        "mttd": mttd_data,
        "mttr": mttr_data,
        "total_incidents": total_incidents,
        "total_flows": total_flows,
        "contained_threats": total_contained,
        "open_incidents": status_map.get("open", 0),
        "resolved_incidents": status_map.get("resolved", 0),
        "false_positive_incidents": status_map.get("false_positive", 0),
        "incidents_by_status": status_map,
        "incidents_by_tier": {
            "HIGH": high_tier_count,
            "MEDIUM": med_tier_count,
            "LOW": low_tier_count,
        },
        "active_containment_blocks": active_blocks,
        "concept_drift_score": round(drift_state.drift_score, 4),
        "is_drifting": drift_state.is_drifting,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
