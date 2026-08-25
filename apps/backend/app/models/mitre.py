from sqlalchemy import Column, String, Text
from app.models.base import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(String, primary_key=True)  # e.g. "T1498", "T1595"
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    description = Column(Text, nullable=False)

    def __repr__(self) -> str:
        return f"<MitreTechnique(id={self.id}, name={self.name}, tactic={self.tactic})>"
