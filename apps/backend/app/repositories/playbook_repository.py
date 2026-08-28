import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.playbook import Playbook


def create_or_update_playbook(
    db: Session,
    incident_id: uuid.UUID,
    content: str,
) -> Playbook:
    """
    Creates or updates the generated playbook for an incident.
    """
    existing = (
        db.query(Playbook).filter(Playbook.incident_id == incident_id).first()
    )
    if existing:
        existing.content = content
        existing.generated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        return existing

    new_playbook = Playbook(
        id=uuid.uuid4(),
        incident_id=incident_id,
        content=content,
        generated_at=datetime.now(timezone.utc),
    )
    db.add(new_playbook)
    db.commit()
    db.refresh(new_playbook)
    return new_playbook


def get_by_incident_id(
    db: Session,
    incident_id: uuid.UUID,
) -> Optional[Playbook]:
    """
    Retrieves the playbook for a specific incident.
    """
    return (
        db.query(Playbook).filter(Playbook.incident_id == incident_id).first()
    )
