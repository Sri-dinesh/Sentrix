from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.domain.drift.service import get_drift_service
from app.repositories import drift_repository

router = APIRouter(prefix="/drift", tags=["drift"])


@router.get("/status", summary="Get real-time concept drift telemetry")
def get_drift_status_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns current statistical concept drift metrics, rolling window sample count,
    and latest distribution shift alerts.
    """
    drift_svc = get_drift_service()
    state = drift_svc.check_drift(db=db)
    return state.to_dict()


@router.get("/events", summary="List historical drift events")
def list_drift_events_endpoint(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves paginated history of statistically significant concept drift occurrences.
    """
    events, total = drift_repository.list_drift_events(
        db=db, limit=limit, offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": str(e.id),
                "drift_score": e.drift_score,
                "triggered_retrain": e.triggered_retrain,
                "detected_at": e.detected_at.isoformat()
                if e.detected_at
                else None,
            }
            for e in events
        ],
    }
