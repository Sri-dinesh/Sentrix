import uuid
from app.worker.celery_app import celery_app
from app.db.session import SessionLocal
from app.domain.playbooks.service import get_playbook_service
from app.domain.drift.service import get_drift_service


@celery_app.task(name="tasks.generate_incident_playbook")
def generate_incident_playbook_task(incident_id_str: str) -> dict:
    """
    Celery background task that synthesizes an incident response playbook asynchronously.
    """
    print(f"[Celery Worker] Starting playbook generation for incident: {incident_id_str}")
    db = SessionLocal()
    try:
        incident_id = uuid.UUID(incident_id_str)
        service = get_playbook_service()
        playbook = service.generate_playbook_for_incident(db=db, incident_id=incident_id)

        if playbook:
            print(f"[Celery Worker] Playbook generated successfully for incident: {incident_id_str}")
            return {
                "status": "success",
                "incident_id": incident_id_str,
                "playbook_id": str(playbook.id),
                "generated_at": playbook.generated_at.isoformat(),
            }
        else:
            print(f"[Celery Worker] Playbook generation returned empty for incident: {incident_id_str}")
            return {"status": "skipped", "incident_id": incident_id_str}
    except Exception as e:
        print(f"[Celery Worker] Error generating playbook for incident {incident_id_str}: {e}")
        return {"status": "error", "error": str(e), "incident_id": incident_id_str}
    finally:
        db.close()


@celery_app.task(name="tasks.periodic_drift_scan")
def periodic_drift_scan_task() -> dict:
    """
    Celery periodic task scanning for concept drift anomalies.
    """
    db = SessionLocal()
    try:
        drift_svc = get_drift_service()
        state = drift_svc.check_drift(db=db)
        return {
            "status": "success",
            "drift_score": state.drift_score,
            "is_drifting": state.is_drifting,
            "sample_count": state.sample_count,
        }
    except Exception as e:
        print(f"[Celery Worker] Error during drift scan: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


@celery_app.task(name="tasks.run_adaptation_cycle")
def run_adaptation_cycle_task(
    trigger: str = "manual",
    requested_by: str = "admin",
    safety_margin: float = 0.02,
) -> dict:
    """
    Celery task that executes continuous model adaptation and fine-tuning with safety gates.
    """
    from app.domain.adaptation.retrain_service import get_retrain_service

    print(f"[Celery Worker] Starting adaptation retraining cycle (trigger: {trigger}, requested_by: {requested_by})")
    db = SessionLocal()
    try:
        service = get_retrain_service()
        results = service.run_adaptation_cycle(
            db=db,
            trigger=trigger,
            safety_margin=safety_margin,
        )
        print(f"[Celery Worker] Retraining cycle complete. Promoted any: {results.get('any_promoted')}")
        return {
            "status": "success",
            "trigger": trigger,
            "requested_by": requested_by,
            "results": results,
        }
    except Exception as e:
        print(f"[Celery Worker] Error during adaptation cycle: {e}")
        return {
            "status": "error",
            "error": str(e),
            "trigger": trigger,
            "requested_by": requested_by,
        }
    finally:
        db.close()
