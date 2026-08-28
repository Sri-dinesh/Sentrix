import os
import json
import uuid
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.detection import Detection
from app.repositories import incident_repository
from app.domain.playbooks.service import get_playbook_service

MAP_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../../../../datasets/mitre/attack_technique_map.json",
    )
)

_attack_mitre_cache: Optional[Dict[str, str]] = None


def load_attack_mitre_mapping() -> Dict[str, str]:
    """
    Loads mapping between attack category strings and MITRE Technique IDs.
    """
    global _attack_mitre_cache
    if _attack_mitre_cache is not None:
        return _attack_mitre_cache

    mapping: Dict[str, str] = {
        "DoS Hulk": "T1498",
        "DDoS": "T1498",
        "PortScan": "T1595.001",
        "SSH-Patator": "T1110",
        "FTP-Patator": "T1110",
        "Web Attack - SQL Injection": "T1190",
        "Bot": "T1584.005",
        "Infiltration": "T1078",
        "Heartbleed": "T1190",
    }

    if os.path.exists(MAP_FILE):
        try:
            with open(MAP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                items: List[Dict[str, Any]] = (
                    data if isinstance(data, list) else data.get("techniques", [])
                )
                for item in items:
                    tech_id = item.get("id")
                    cats = item.get("attack_categories", item.get("mapped_attacks", []))
                    for attack in cats:
                        mapping[attack] = tech_id
        except Exception as e:
            print(f"Warning: Failed to load MITRE attack map: {e}")

    _attack_mitre_cache = mapping
    return _attack_mitre_cache


def resolve_mitre_technique(attack_type: Optional[str]) -> Optional[str]:
    """
    Resolves attack name string to MITRE Technique ID.
    """
    if not attack_type or attack_type == "BENIGN":
        return None

    mapping = load_attack_mitre_mapping()
    # Exact match
    if attack_type in mapping:
        return mapping[attack_type]

    # Partial / case-insensitive match
    for key, val in mapping.items():
        if key.lower() in attack_type.lower() or attack_type.lower() in key.lower():
            return val

    return "T1000"


class IncidentService:
    """
    Service managing incident creation, MITRE ATT&CK mapping, and async playbook triggering.
    """

    def create_incident_from_detection(
        self,
        db: Session,
        detection_id: uuid.UUID,
        action_taken: str = "MONITOR",
        status: str = "open",
        trigger_playbook: bool = True,
        run_sync: bool = False,
    ) -> Incident:
        """
        Creates an incident linked to a detection.
        Maps the attack to MITRE ATT&CK technique and triggers playbook synthesis.
        """
        detection = (
            db.query(Detection).filter(Detection.id == detection_id).first()
        )
        if not detection:
            raise ValueError(f"Detection {detection_id} not found.")

        mitre_id = resolve_mitre_technique(detection.attack_type)

        incident = incident_repository.create_incident(
            db=db,
            detection_id=detection.id,
            action_taken=action_taken,
            mitre_technique_id=mitre_id,
            status=status,
        )

        if trigger_playbook:
            if run_sync:
                try:
                    pb_service = get_playbook_service()
                    pb_service.generate_playbook_for_incident(
                        db=db, incident_id=incident.id
                    )
                except Exception as e:
                    print(f"Warning: Synchronous playbook generation failed: {e}")
            else:
                try:
                    from app.worker.tasks import generate_incident_playbook_task

                    generate_incident_playbook_task.delay(str(incident.id))
                except Exception as e:
                    print(
                        f"Celery queueing unavailable ({e}). Generating playbook synchronously..."
                    )
                    try:
                        pb_service = get_playbook_service()
                        pb_service.generate_playbook_for_incident(
                            db=db, incident_id=incident.id
                        )
                    except Exception as err:
                        print(f"Fallback playbook generation error: {err}")

        return incident


# Global singleton instance
_incident_service_instance: Optional[IncidentService] = None


def get_incident_service() -> IncidentService:
    global _incident_service_instance
    if _incident_service_instance is None:
        _incident_service_instance = IncidentService()
    return _incident_service_instance
