import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base


class Flow(Base):
    __tablename__ = "flows"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    captured_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    src_ip = Column(String, index=True, nullable=False)
    dst_ip = Column(String, index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    packet_count = Column(Integer, nullable=False, default=1)
    byte_count = Column(Integer, nullable=False, default=0)
    duration = Column(Float, nullable=False, default=0.0)
    raw_features = Column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_flows_src_ip_captured_at", "src_ip", "captured_at"),
    )

    def __repr__(self) -> str:
        return f"<Flow(id={self.id}, src={self.src_ip}:{self.src_port}, dst={self.dst_ip}:{self.dst_port})>"
