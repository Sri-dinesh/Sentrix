import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.models.base import Base


class Detection(Base):
    __tablename__ = "detections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flow_id = Column(
        UUID(as_uuid=True),
        ForeignKey("flows.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    anomaly_score = Column(Float, nullable=False)
    is_anomalous = Column(Boolean, nullable=False, default=False)
    attack_type = Column(String, nullable=True)
    classifier_margin = Column(Float, nullable=True)
    drift_score = Column(Float, nullable=True)
    confidence_score = Column(Float, index=True, nullable=False)
    confidence_breakdown = Column(JSONB, nullable=False, default=dict)
    detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "confidence_score >= 0.0 AND confidence_score <= 1.0",
            name="check_confidence_score_range",
        ),
    )

    # Relationships
    flow = relationship("Flow", backref="detections")

    def __repr__(self) -> str:
        return f"<Detection(id={self.id}, anomalous={self.is_anomalous}, confidence={self.confidence_score})>"
