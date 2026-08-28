import uuid
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.incident import Incident
from app.repositories import incident_repository, playbook_repository
from app.domain.playbooks.service import get_playbook_service
from app.domain.containment.feedback import handle_incident_resolution

router = APIRouter(prefix="/incidents", tags=["incidents"])


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(
        ...,
        pattern="^(open|investigating|contained|resolved|false_positive)$",
        description="Updated lifecycle status",
    )


@router.get("", summary="List incidents")
def list_incidents_endpoint(
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by status"
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves a paginated list of security incidents with MITRE technique and detection summary.
    """
    incidents, total = incident_repository.list_incidents(
        db=db, status=status_filter, limit=limit, offset=offset
    )

    items = []
    for inc in incidents:
        det = inc.detection
        flow = det.flow if det else None
        mt = inc.mitre_technique

        items.append(
            {
                "id": str(inc.id),
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
                "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
                "status": inc.status,
                "action_taken": inc.action_taken,
                "mitre_technique_id": inc.mitre_technique_id,
                "mitre_technique": {
                    "id": mt.id,
                    "name": mt.name,
                    "tactic": mt.tactic,
                }
                if mt
                else None,
                "detection": {
                    "id": str(det.id),
                    "attack_type": det.attack_type,
                    "confidence_score": det.confidence_score,
                    "anomaly_score": det.anomaly_score,
                }
                if det
                else None,
                "flow": {
                    "id": str(flow.id),
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                }
                if flow
                else None,
            }
        )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.get("/{incident_id}", summary="Get incident details")
def get_incident_by_id_endpoint(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves full incident forensic data, MITRE ATT&CK taxonomy, flow telemetry, and generated playbook.
    """
    incident = incident_repository.get_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )

    det = incident.detection
    flow = det.flow if det else None
    mt = incident.mitre_technique
    playbook = playbook_repository.get_by_incident_id(db, incident.id)

    return {
        "id": str(incident.id),
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "status": incident.status,
        "action_taken": incident.action_taken,
        "resolved_by": str(incident.resolved_by) if incident.resolved_by else None,
        "mitre_technique": {
            "id": mt.id,
            "name": mt.name,
            "tactic": mt.tactic,
            "description": mt.description,
        }
        if mt
        else None,
        "detection": {
            "id": str(det.id),
            "attack_type": det.attack_type,
            "confidence_score": det.confidence_score,
            "anomaly_score": det.anomaly_score,
            "classifier_margin": det.classifier_margin,
            "drift_score": det.drift_score,
            "confidence_breakdown": det.confidence_breakdown,
        }
        if det
        else None,
        "flow": {
            "id": str(flow.id),
            "captured_at": flow.captured_at.isoformat() if flow and flow.captured_at else None,
            "src_ip": flow.src_ip if flow else None,
            "dst_ip": flow.dst_ip if flow else None,
            "src_port": flow.src_port if flow else None,
            "dst_port": flow.dst_port if flow else None,
            "protocol": flow.protocol if flow else None,
            "packet_count": flow.packet_count if flow else None,
            "byte_count": flow.byte_count if flow else None,
            "duration": flow.duration if flow else None,
            "raw_features": flow.raw_features if flow else {},
        }
        if flow
        else None,
        "playbook": {
            "id": str(playbook.id),
            "content": playbook.content,
            "generated_at": playbook.generated_at.isoformat(),
        }
        if playbook
        else None,
    }


@router.patch("/{incident_id}/status", summary="Update incident lifecycle status")
def update_incident_status_endpoint(
    incident_id: uuid.UUID,
    req: UpdateIncidentStatusRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Updates the lifecycle status of an incident.
    If transitioned to 'false_positive', automatically rolls back containment rules
    and stages the benign flow into the active learning candidate buffer.
    """
    incident = handle_incident_resolution(
        db=db,
        incident_id=incident_id,
        new_status=req.status,
        resolved_by=current_user.id,
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )

    return {
        "status": "success",
        "incident_id": str(incident.id),
        "new_status": incident.status,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


@router.post("/{incident_id}/playbook/generate", summary="Trigger playbook generation")
def generate_playbook_endpoint(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Synthesizes or regenerates an AI incident containment playbook using Ollama.
    """
    incident = incident_repository.get_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )

    service = get_playbook_service()
    playbook = service.generate_playbook_for_incident(db=db, incident_id=incident_id)
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate playbook for incident.",
        )

    return {
        "status": "success",
        "playbook_id": str(playbook.id),
        "incident_id": str(incident.id),
        "generated_at": playbook.generated_at.isoformat(),
        "content": playbook.content,
    }
