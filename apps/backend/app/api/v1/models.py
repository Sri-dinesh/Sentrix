import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_user, require_admin
from app.models.user import User
from app.models.model_version import ModelVersion
from app.repositories import model_repository

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", summary="List versioned model checkpoints")
def list_models_endpoint(
    component: Optional[str] = Query(
        None, description="Filter by component: 'autoencoder' or 'classifier'"
    ),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Lists historical model versions, checkpoint storage paths, and validation metrics.
    """
    versions = model_repository.list_model_versions(
        db=db, component=component, limit=limit
    )
    return {
        "total": len(versions),
        "items": [
            {
                "id": str(m.id),
                "component": m.component,
                "version_tag": m.version_tag,
                "storage_path": m.storage_path,
                "metrics": m.metrics,
                "is_active": m.is_active,
                "trained_at": m.trained_at.isoformat() if m.trained_at else None,
            }
            for m in versions
        ],
    }


@router.post("/{version_id}/activate", summary="Promote model version to active (Admin Only)")
def activate_model_endpoint(
    version_id: uuid.UUID,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Promotes the selected model version to active production status.
    Protected strictly by role gating: Administrator privilege required.
    """
    target = model_repository.set_active_version(db, version_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version {version_id} not found.",
        )

    return {
        "status": "success",
        "message": f"Activated version {target.version_tag} for component {target.component}.",
        "model": {
            "id": str(target.id),
            "component": target.component,
            "version_tag": target.version_tag,
            "is_active": target.is_active,
        },
    }
