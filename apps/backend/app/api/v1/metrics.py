from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.schemas.metrics import MTTDResponse, MTTRResponse, MetricsOverviewResponse
from app.repositories import metrics_repository

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get(
    "/mttd",
    response_model=MTTDResponse,
    summary="Get Mean Time to Detect (MTTD) metric",
)
def get_mttd_endpoint(
    window_hours: int = Query(24, ge=1, le=720, description="Rolling time window in hours"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns Mean Time to Detect (MTTD) across flow capture to anomaly scoring.
    """
    return metrics_repository.compute_mttd(db=db, window_hours=window_hours)


@router.get(
    "/mttr",
    response_model=MTTRResponse,
    summary="Get Mean Time to Remediate (MTTR) metric",
)
def get_mttr_endpoint(
    window_hours: int = Query(24, ge=1, le=720, description="Rolling time window in hours"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns Mean Time to Remediate / Respond (MTTR) for resolved incidents.
    """
    return metrics_repository.compute_mttr(db=db, window_hours=window_hours)


@router.get(
    "/overview",
    response_model=MetricsOverviewResponse,
    summary="Get comprehensive executive SOC metrics overview",
)
def get_metrics_overview_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns aggregated executive telemetry:
    - MTTD and MTTR latencies
    - Total incidents and containment actions
    - Breakdown by status and response tier
    - Active line-rate containment blocks
    - Current concept drift score
    """
    return metrics_repository.get_metrics_overview(db=db)
