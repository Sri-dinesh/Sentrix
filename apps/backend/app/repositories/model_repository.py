import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.model_version import ModelVersion


def get_active_model(db: Session, component: str) -> Optional[ModelVersion]:
    """
    Retrieves the currently active production model version for a component.
    component: 'autoencoder' or 'classifier'
    """
    return (
        db.query(ModelVersion)
        .filter(ModelVersion.component == component, ModelVersion.is_active == True)
        .order_by(ModelVersion.trained_at.desc())
        .first()
    )


def list_model_versions(
    db: Session,
    component: Optional[str] = None,
    limit: int = 50,
) -> List[ModelVersion]:
    """
    Lists historical model versions, optionally filtered by component.
    """
    query = db.query(ModelVersion)
    if component:
        query = query.filter(ModelVersion.component == component)
    return query.order_by(ModelVersion.trained_at.desc()).limit(limit).all()


def register_model_version(
    db: Session,
    component: str,
    version_tag: str,
    storage_path: str,
    metrics: Dict[str, Any],
    set_active: bool = True,
) -> ModelVersion:
    """
    Registers a new trained model version.
    If set_active is True, deactivates previous active versions for this component.
    """
    if set_active:
        db.query(ModelVersion).filter(
            ModelVersion.component == component, ModelVersion.is_active == True
        ).update({"is_active": False})

    new_version = ModelVersion(
        component=component,
        version_tag=version_tag,
        storage_path=storage_path,
        metrics=metrics,
        is_active=set_active,
    )
    db.add(new_version)
    db.commit()
    db.refresh(new_version)
    return new_version


def set_active_version(db: Session, version_id: uuid.UUID) -> Optional[ModelVersion]:
    """
    Promotes a specific model version to active and deactivates others.
    """
    target = db.query(ModelVersion).filter(ModelVersion.id == version_id).first()
    if not target:
        return None

    db.query(ModelVersion).filter(
        ModelVersion.component == target.component, ModelVersion.is_active == True
    ).update({"is_active": False})

    target.is_active = True
    db.commit()
    db.refresh(target)
    return target
