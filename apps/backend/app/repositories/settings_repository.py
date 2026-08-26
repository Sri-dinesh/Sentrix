import time
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.settings import SettingsModel

_cached_settings: Optional[Dict[str, float]] = None
_cache_timestamp: float = 0.0
CACHE_TTL = 30.0  # 30 seconds cache


def get_default_settings_dict() -> Dict[str, float]:
    return {
        "confidence_weight_anomaly": 0.40,
        "confidence_weight_classifier": 0.40,
        "confidence_weight_drift": 0.20,
        "tier_high_threshold": 0.85,
        "tier_medium_threshold": 0.50,
        "anomaly_base_threshold": 0.026147,
    }


def get_settings(db: Session, use_cache: bool = True) -> SettingsModel:
    """
    Retrieves the system settings row. Creates default row if missing.
    """
    record = db.query(SettingsModel).first()
    if not record:
        defaults = get_default_settings_dict()
        record = SettingsModel(
            confidence_weight_anomaly=defaults["confidence_weight_anomaly"],
            confidence_weight_classifier=defaults["confidence_weight_classifier"],
            confidence_weight_drift=defaults["confidence_weight_drift"],
            tier_high_threshold=defaults["tier_high_threshold"],
            tier_medium_threshold=defaults["tier_medium_threshold"],
            anomaly_base_threshold=defaults["anomaly_base_threshold"],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def get_settings_dict(db: Optional[Session] = None) -> Dict[str, float]:
    """
    Returns settings as a dictionary, using cache where valid.
    """
    global _cached_settings, _cache_timestamp
    now = time.time()

    if _cached_settings and (now - _cache_timestamp < CACHE_TTL):
        return _cached_settings

    if db is not None:
        try:
            record = get_settings(db)
            _cached_settings = {
                "confidence_weight_anomaly": record.confidence_weight_anomaly,
                "confidence_weight_classifier": record.confidence_weight_classifier,
                "confidence_weight_drift": record.confidence_weight_drift,
                "tier_high_threshold": record.tier_high_threshold,
                "tier_medium_threshold": record.tier_medium_threshold,
                "anomaly_base_threshold": record.anomaly_base_threshold,
            }
            _cache_timestamp = now
            return _cached_settings
        except Exception as e:
            print(f"Warning: Failed to fetch settings from DB: {e}")

    if _cached_settings:
        return _cached_settings

    return get_default_settings_dict()


def update_settings(db: Session, update_data: Dict[str, Any]) -> SettingsModel:
    """
    Updates the system settings row and invalidates in-memory cache.
    """
    global _cached_settings, _cache_timestamp
    record = get_settings(db)

    for field in [
        "confidence_weight_anomaly",
        "confidence_weight_classifier",
        "confidence_weight_drift",
        "tier_high_threshold",
        "tier_medium_threshold",
        "anomaly_base_threshold",
    ]:
        if field in update_data and update_data[field] is not None:
            setattr(record, field, float(update_data[field]))

    db.commit()
    db.refresh(record)

    # Invalidate cache
    _cached_settings = None
    _cache_timestamp = 0.0

    return record
