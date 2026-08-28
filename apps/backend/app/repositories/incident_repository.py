import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.incident import Incident


def create_incident(
    db: Session,
    detection_id: uuid.UUID,
    action_taken: str = "MONITOR",
    mitre_technique_id: Optional[str] = None,
    status: str = "open",
) -> Incident:
    """
    Persists a new security incident triggered by an anomalous detection.
    """
    incident = Incident(
        id=uuid.uuid4(),
        detection_id=detection_id,
        status=status,
        action_taken=action_taken,
        mitre_technique_id=mitre_technique_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def get_by_id(db: Session, incident_id: uuid.UUID) -> Optional[Incident]:
    """Retrieves an incident by primary UUID."""
    return db.query(Incident).filter(Incident.id == incident_id).first()


def get_by_detection_id(
    db: Session, detection_id: uuid.UUID
) -> Optional[Incident]:
    """Retrieves an incident by its associated detection UUID."""
    return (
        db.query(Incident).filter(Incident.detection_id == detection_id).first()
    )


def list_incidents(
    db: Session,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Incident], int]:
    """
    Retrieves paginated list of incidents, optionally filtered by status.
    """
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)

    total_count = query.count()
    incidents = (
        query.order_by(desc(Incident.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return incidents, total_count


def update_status(
    db: Session,
    incident_id: uuid.UUID,
    status: str,
    resolved_by: Optional[uuid.UUID] = None,
) -> Optional[Incident]:
    """
    Updates the lifecycle status of an incident ('open', 'investigating', 'contained', 'resolved', 'false_positive').
    """
    incident = get_by_id(db, incident_id)
    if not incident:
        return None

    incident.status = status
    if status in ("resolved", "contained", "false_positive"):
        incident.resolved_at = datetime.now(timezone.utc)
        if resolved_by:
            incident.resolved_by = resolved_by

    db.commit()
    db.refresh(incident)
    return incident
