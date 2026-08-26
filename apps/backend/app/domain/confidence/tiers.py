from enum import Enum
from typing import Dict, Any


class Tier(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def classify_tier(
    confidence_score: float,
    tier_high_threshold: float = 0.85,
    tier_medium_threshold: float = 0.50,
) -> Tier:
    """
    Classifies a calibrated confidence score into actionable response tiers:
    - HIGH (>= 0.85): Autonomous containment candidate
    - MEDIUM (0.50 <= score < 0.85): Investigation & rate-limiting candidate
    - LOW (< 0.50): Passive monitoring & audit logging
    """
    score = float(confidence_score)
    if score >= tier_high_threshold:
        return Tier.HIGH
    elif score >= tier_medium_threshold:
        return Tier.MEDIUM
    else:
        return Tier.LOW


def get_recommended_action(tier: Tier) -> str:
    """
    Returns default recommended action based on response tier.
    """
    if tier == Tier.HIGH:
        return "BLOCK"
    elif tier == Tier.MEDIUM:
        return "RATE_LIMIT"
    else:
        return "MONITOR"
