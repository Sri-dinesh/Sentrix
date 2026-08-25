import os
import sys

# Ensure apps/backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.models.settings import SettingsModel


def seed_default_settings():
    db = SessionLocal()
    try:
        existing = db.query(SettingsModel).first()
        if existing:
            print(f"Default settings row already exists: ID={existing.id}")
            return existing

        default_settings = SettingsModel(
            confidence_weight_anomaly=0.4,
            confidence_weight_classifier=0.4,
            confidence_weight_drift=0.2,
            tier_high_threshold=0.85,
            tier_medium_threshold=0.50,
            anomaly_base_threshold=0.05,
        )
        db.add(default_settings)
        db.commit()
        db.refresh(default_settings)
        print(f"Successfully seeded default settings: ID={default_settings.id}")
        return default_settings
    except Exception as e:
        db.rollback()
        print(f"Failed to seed settings: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_default_settings()
