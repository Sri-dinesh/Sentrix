import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.models.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    status = Column(
        String,
        index=True,
        nullable=False,
        default="open",
    )
    action_taken = Column(
        String,
        nullable=False,
        default="MONITOR",
    )  # "MONITOR", "INVESTIGATE", "RATE_LIMIT", "BLOCK"
    mitre_technique_id = Column(
        String,
        ForeignKey("mitre_techniques.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', 'false_positive')",
            name="check_incident_status_valid",
        ),
    )

    # Relationships
    detection = relationship("Detection", backref="incident", uselist=False)
    mitre_technique = relationship("MitreTechnique", backref="incidents")
    resolver = relationship("User", backref="resolved_incidents")

    def __repr__(self) -> str:
        return f"<Incident(id={self.id}, status={self.status}, action={self.action_taken})>"
