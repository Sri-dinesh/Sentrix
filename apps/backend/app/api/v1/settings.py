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
