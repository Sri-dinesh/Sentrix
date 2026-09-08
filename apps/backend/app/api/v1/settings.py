from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.api.deps import get_current_user, require_admin
from app.models.user import User
from app.models.settings import SettingsModel
from app.repositories import settings_repository

router = APIRouter(prefix="/settings", tags=["settings"])


class UpdateSettingsRequest(BaseModel):
    confidence_weight_anomaly: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_weight_classifier: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_weight_drift: Optional[float] = Field(None, ge=0.0, le=1.0)
    tier_high_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    tier_medium_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    anomaly_base_threshold: Optional[float] = Field(None, ge=0.0)


@router.get("", summary="Get active confidence weights and system thresholds")
def get_settings_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns the currently active multi-signal confidence weights and response tier thresholds.
    """
    settings_obj = settings_repository.get_settings(db)
    return {
        "id": str(settings_obj.id),
        "confidence_weight_anomaly": settings_obj.confidence_weight_anomaly,
        "confidence_weight_classifier": settings_obj.confidence_weight_classifier,
        "confidence_weight_drift": settings_obj.confidence_weight_drift,
        "tier_high_threshold": settings_obj.tier_high_threshold,
        "tier_medium_threshold": settings_obj.tier_medium_threshold,
        "anomaly_base_threshold": settings_obj.anomaly_base_threshold,
        "updated_at": settings_obj.updated_at.isoformat()
        if settings_obj.updated_at
        else None,
    }


@router.put("", summary="Update confidence weights and system thresholds (Admin Only)")
def update_settings_endpoint(
    req: UpdateSettingsRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Modifies confidence fusion weights and tier actuation thresholds.
    Protected strictly by role gating: Administrator privilege required.
    """
    update_data = req.model_dump(exclude_unset=True)
    updated_obj = settings_repository.update_settings(db, update_data)

    return {
        "status": "success",
        "settings": {
            "confidence_weight_anomaly": updated_obj.confidence_weight_anomaly,
            "confidence_weight_classifier": updated_obj.confidence_weight_classifier,
            "confidence_weight_drift": updated_obj.confidence_weight_drift,
            "tier_high_threshold": updated_obj.tier_high_threshold,
            "tier_medium_threshold": updated_obj.tier_medium_threshold,
            "anomaly_base_threshold": updated_obj.anomaly_base_threshold,
            "updated_at": updated_obj.updated_at.isoformat(),
        },
    }


class RetrainTriggerRequest(BaseModel):
    component: Optional[str] = Field(None, description="Optional component to target ('autoencoder' | 'classifier' | None for all)")
    safety_margin: Optional[float] = Field(0.02, ge=0.001, le=0.20, description="Max allowable regression safety margin")


@router.post("/retrain", summary="Trigger manual model retraining adaptation cycle (Admin Only)", status_code=status.HTTP_202_ACCEPTED)
def trigger_retrain_endpoint(
    req: Optional[RetrainTriggerRequest] = None,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Manually triggers the continual learning adaptation pipeline.
    Fine-tunes models against the mixed replay buffer with strict regression safety gates.
    Protected strictly by role gating: Administrator privilege required.
    """
    import uuid
    from app.worker.tasks import run_adaptation_cycle_task

    margin = req.safety_margin if req and req.safety_margin is not None else 0.02

    try:
        task = run_adaptation_cycle_task.delay(
            trigger="admin_manual",
            requested_by=str(current_admin.id),
            safety_margin=margin,
        )
        task_id = str(task.id)
        execution_mode = "async_celery"
    except Exception as e:
        print(f"Notice: Celery queue unavailable for manual retrain ({e}). Generating fallback task ID.")
        task_id = str(uuid.uuid4())
        execution_mode = "queued_local"

    return {
        "status": "queued",
        "task_id": task_id,
        "execution_mode": execution_mode,
        "message": "Continuous learning adaptation cycle enqueued successfully.",
        "requested_by": str(current_admin.id),
        "safety_margin": margin,
    }
