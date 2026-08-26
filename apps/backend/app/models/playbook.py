import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Text, DateTime, ForeignKey, Uuid
from sqlalchemy.orm import relationship
from app.models.base import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id = Column(
        Uuid,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    content = Column(Text, nullable=False)
    generated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship
    incident = relationship("Incident", backref="playbook", uselist=False)

    def __repr__(self) -> str:
        return f"<Playbook(id={self.id}, incident_id={self.incident_id})>"
