import json
import os
import sys

# Ensure apps/backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.models.mitre import MitreTechnique


def seed_mitre_techniques():
    json_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../../../../datasets/mitre/attack_technique_map.json",
        )
    )

    if not os.path.exists(json_path):
        print(f"Error: MITRE attack map not found at {json_path}")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    db = SessionLocal()
    inserted = 0
    updated = 0

    try:
        for item in techniques:
            tech_id = item["id"]
            name = item["name"]
            tactic = item["tactic"]
            description = item["description"]

            existing = db.query(MitreTechnique).filter(MitreTechnique.id == tech_id).first()
            if existing:
                existing.name = name
                existing.tactic = tactic
                existing.description = description
                updated += 1
            else:
                new_tech = MitreTechnique(
                    id=tech_id,
                    name=name,
                    tactic=tactic,
                    description=description,
                )
                db.add(new_tech)
                inserted += 1

        db.commit()
        print(f"Successfully seeded MITRE techniques: {inserted} inserted, {updated} updated.")
    except Exception as e:
        db.rollback()
        print(f"Failed to seed MITRE techniques: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_mitre_techniques()
