import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    component = Column(String, index=True, nullable=False)  # "autoencoder" or "classifier"
    version_tag = Column(String, nullable=False)
    storage_path = Column(String, nullable=False)  # Supabase Storage path
    metrics = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, default=False, nullable=False)
    trained_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ModelVersion(component={self.component}, version={self.version_tag}, active={self.is_active})>"
