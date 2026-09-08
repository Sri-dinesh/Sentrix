"""
Celery Task Module for Model Retraining and Continual Learning Adaptation.
Re-exports task definition for modular imports.
"""
from app.worker.tasks import run_adaptation_cycle_task

__all__ = ["run_adaptation_cycle_task"]
