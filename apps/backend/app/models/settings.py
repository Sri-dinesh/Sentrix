import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Float, DateTime, Uuid
from app.models.base import Base


class SettingsModel(Base):
    __tablename__ = "settings"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    confidence_weight_anomaly = Column(Float, nullable=False, default=0.4)
    confidence_weight_classifier = Column(Float, nullable=False, default=0.4)
    confidence_weight_drift = Column(Float, nullable=False, default=0.2)
    tier_high_threshold = Column(Float, nullable=False, default=0.85)
    tier_medium_threshold = Column(Float, nullable=False, default=0.50)
    anomaly_base_threshold = Column(Float, nullable=False, default=0.05)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Settings(w1={self.confidence_weight_anomaly}, w2={self.confidence_weight_classifier}, w3={self.confidence_weight_drift})>"
