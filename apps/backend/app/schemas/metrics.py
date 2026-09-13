from typing import Dict, Optional
from pydantic import BaseModel, Field


class MTTDResponse(BaseModel):
    mean_seconds: float = Field(..., description="Mean Time to Detect (MTTD) in seconds")
    sample_count: int = Field(..., description="Number of evaluated detection samples")
    window_hours: int = Field(..., description="Evaluation time window in hours")
    timestamp: str = Field(..., description="Evaluation timestamp")


class MTTRResponse(BaseModel):
    mean_seconds: float = Field(..., description="Mean Time to Remediate (MTTR) in seconds")
    resolved_count: int = Field(..., description="Number of resolved incidents evaluated")
    window_hours: int = Field(..., description="Evaluation time window in hours")
    timestamp: str = Field(..., description="Evaluation timestamp")


class MetricsOverviewResponse(BaseModel):
    mttd: MTTDResponse
    mttr: MTTRResponse
    total_incidents: int
    total_flows: int
    contained_threats: int
    open_incidents: int
    resolved_incidents: int
    false_positive_incidents: int
    incidents_by_status: Dict[str, int]
    incidents_by_tier: Dict[str, int]
    active_containment_blocks: int
    concept_drift_score: float
    is_drifting: bool
    generated_at: str
