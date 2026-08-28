import uuid
from typing import Optional
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.playbook import Playbook
from app.core.llm import get_ollama_client
from app.domain.playbooks.prompt import SYSTEM_PROMPT, build_playbook_prompt
from app.repositories import playbook_repository


class PlaybookService:
    """
    Service responsible for synthesizing and managing Incident Playbooks.
    """

    def __init__(self):
        self.llm_client = get_ollama_client()

    def generate_playbook_for_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> Optional[Playbook]:
        """
        Gathers contextual metadata for the incident and synthesizes a playbook using Ollama.
        Persists the result in the database.
        """
        incident = (
            db.query(Incident).filter(Incident.id == incident_id).first()
        )
        if not incident or not incident.detection:
            print(
                f"Warning: Incident {incident_id} or its detection record not found."
            )
            return None

        detection = incident.detection
        flow = detection.flow

        # Formulate telemetry dictionaries
        incident_data = {
            "id": str(incident.id),
            "status": incident.status,
            "action_taken": incident.action_taken,
        }

        detection_data = {
            "attack_type": detection.attack_type,
            "confidence_score": detection.confidence_score,
            "anomaly_score": detection.anomaly_score,
            "classifier_margin": detection.classifier_margin,
            "drift_score": detection.drift_score,
        }

        flow_data = {
            "src_ip": flow.src_ip if flow else "10.0.0.1",
            "dst_ip": flow.dst_ip if flow else "192.168.1.1",
            "src_port": flow.src_port if flow else 0,
            "dst_port": flow.dst_port if flow else 80,
            "protocol": flow.protocol if flow else "TCP",
            "packet_count": flow.packet_count if flow else 1,
            "byte_count": flow.byte_count if flow else 64,
            "duration": flow.duration if flow else 0.0,
        }

        mitre_data = None
        if incident.mitre_technique:
            mt = incident.mitre_technique
            mitre_data = {
                "id": mt.id,
                "name": mt.name,
                "tactic": mt.tactic,
                "description": mt.description,
                "mitigation": getattr(
                    mt,
                    "mitigation",
                    "Filter offending traffic at network ingress perimeter.",
                ),
            }

        # Build prompt
        prompt = build_playbook_prompt(
            incident_data=incident_data,
            detection_data=detection_data,
            flow_data=flow_data,
            mitre_data=mitre_data,
        )

        # Generate markdown via Ollama (or fallback synthesizer)
        playbook_content = self.llm_client.generate_sync(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            temperature=0.2,
        )

        # Save in database
        playbook = playbook_repository.create_or_update_playbook(
            db=db,
            incident_id=incident.id,
            content=playbook_content,
        )
        return playbook


# Global singleton instance
_playbook_service_instance: Optional[PlaybookService] = None


def get_playbook_service() -> PlaybookService:
    global _playbook_service_instance
    if _playbook_service_instance is None:
        _playbook_service_instance = PlaybookService()
    return _playbook_service_instance
