import uuid
from typing import Optional, List, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.drift_event import DriftEvent


def record_drift_event(
    db: Session,
    drift_score: float,
    triggered_retrain: bool = False,
) -> DriftEvent:
    """
    Records a statistically significant concept drift event in the database.
    """
    event = DriftEvent(
        id=uuid.uuid4(),
        drift_score=float(drift_score),
        triggered_retrain=triggered_retrain,
        detected_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_latest_drift_event(db: Session) -> Optional[DriftEvent]:
    """Retrieves the most recent drift event."""
    return db.query(DriftEvent).order_by(desc(DriftEvent.detected_at)).first()


def list_drift_events(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[DriftEvent], int]:
    """
    Retrieves paginated history of drift events.
    """
    query = db.query(DriftEvent)
    total_count = query.count()
    events = (
        query.order_by(desc(DriftEvent.detected_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return events, total_count
