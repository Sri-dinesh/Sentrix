from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.models.user import User
from app.domain.containment.service import get_containment_service

router = APIRouter(prefix="/containment", tags=["containment"])


class ContainmentActionRequest(BaseModel):
    src_ip: str = Field(..., description="Target source IPv4 address to contain")
    action: Optional[str] = Field("BLOCK", description="'BLOCK' or 'RATE_LIMIT'")
    dpid: Optional[int] = Field(None, description="OpenFlow switch DPID (optional)")


class UnblockRequest(BaseModel):
    src_ip: str = Field(..., description="Target source IPv4 address to release")
    dpid: Optional[int] = Field(None, description="OpenFlow switch DPID (optional)")


@router.get("/active", summary="List actively contained IP addresses")
def list_active_containment_endpoint(
    current_user: User = Depends(get_current_user),
):
    """
    Returns list of all IP addresses currently blocked or throttled across SDN & host firewalls.
    """
    service = get_containment_service()
    blocked_ips = service.list_active_contained_ips()
    history = service.get_history(limit=20)

    return {
        "active_blocked_ips": blocked_ips,
        "total_active": len(blocked_ips),
        "recent_actions": [h.to_dict() for h in history],
    }


@router.post("/block", summary="Manually trigger IP containment")
def manual_block_endpoint(
    req: ContainmentActionRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Manually enforces DROP or RATE_LIMIT containment on the target source IP.
    """
    service = get_containment_service()
    result = service.apply_containment(
        src_ip=req.src_ip,
        action=req.action or "BLOCK",
        dpid=req.dpid,
    )
    return result.to_dict()


@router.post("/unblock", summary="Manually release IP containment")
def manual_unblock_endpoint(
    req: UnblockRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Manually releases containment rules for the specified IP address across SDN and host firewalls.
    """
    service = get_containment_service()
    result = service.lift_containment(
        src_ip=req.src_ip,
        dpid=req.dpid,
    )
    return result.to_dict()
