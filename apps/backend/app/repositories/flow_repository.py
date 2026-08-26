import uuid
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.flow import Flow


def create_flow(db: Session, flow_dict: Dict[str, Any]) -> Flow:
    """
    Persists a network flow record in the database.
    """
    flow = Flow(
        id=flow_dict.get("id", uuid.uuid4()),
        captured_at=flow_dict.get("captured_at", datetime.now()),
        src_ip=flow_dict["src_ip"],
        dst_ip=flow_dict["dst_ip"],
        src_port=int(flow_dict.get("src_port", 0)),
        dst_port=int(flow_dict.get("dst_port", 0)),
        protocol=str(flow_dict.get("protocol", "TCP")),
        packet_count=int(flow_dict.get("packet_count", 1)),
        byte_count=int(flow_dict.get("byte_count", 0)),
        duration=float(flow_dict.get("duration", 0.0)),
        raw_features=flow_dict.get("raw_features", {}),
    )
    db.add(flow)
    db.commit()
    db.refresh(flow)
    return flow


def get_by_id(db: Session, flow_id: uuid.UUID) -> Optional[Flow]:
    """Retrieves a flow by primary UUID key."""
    return db.query(Flow).filter(Flow.id == flow_id).first()


def search_flows(
    db: Session,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Flow], int]:
    """
    Performs forensic searches on flows with multi-criteria filtering and pagination.
    """
    query = db.query(Flow)

    if src_ip:
        query = query.filter(Flow.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(Flow.dst_ip.ilike(f"%{dst_ip}%"))
    if protocol:
        query = query.filter(Flow.protocol.ilike(protocol))
    if date_from:
        query = query.filter(Flow.captured_at >= date_from)
    if date_to:
        query = query.filter(Flow.captured_at <= date_to)

    total_count = query.count()
    flows = (
        query.order_by(desc(Flow.captured_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return flows, total_count
