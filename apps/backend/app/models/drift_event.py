import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Float, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from app.models.base import Base


class DriftEvent(Base):
    __tablename__ = "drift_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    drift_score = Column(Float, nullable=False)
    triggered_retrain = Column(Boolean, default=False, nullable=False)
    detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<DriftEvent(id={self.id}, score={self.drift_score}, retrain={self.triggered_retrain})>"
