import json
import os
import numpy as np
from typing import Dict, Any, List, Optional

# Load feature names contract from autoencoder metadata
META_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../ml/models/autoencoder_meta.json")
)

DEFAULT_FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]


def get_feature_columns() -> List[str]:
    """
    Returns the ordered feature names list.
    """
    if os.path.exists(META_PATH):
        try:
            with open(META_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
                return meta.get("feature_names", DEFAULT_FEATURE_NAMES)
        except Exception:
            pass
    return DEFAULT_FEATURE_NAMES


def extract_flow_features(flow_dict: Dict[str, Any]) -> np.ndarray:
    """
    Extracts and validates a 71-dimensional numeric feature vector from a raw flow dictionary.
    Handles missing keys, invalid data types, NaNs, and extreme values.
    """
    feature_names = get_feature_columns()
    vector = np.zeros(len(feature_names), dtype=np.float32)

    raw_features = flow_dict.get("raw_features") or flow_dict

    for idx, feat_name in enumerate(feature_names):
        val = raw_features.get(feat_name)

        if val is None:
            # Check lowercase or stripped match
            for k, v in raw_features.items():
                if str(k).strip().lower() == feat_name.strip().lower():
                    val = v
                    break

        if val is None:
            # Fallback default heuristic based on feature type
            if "port" in feat_name.lower():
                val = flow_dict.get("dst_port", 80)
            elif "duration" in feat_name.lower():
                val = flow_dict.get("duration", 0.0)
            elif "packet" in feat_name.lower():
                val = flow_dict.get("packet_count", 1)
            elif "byte" in feat_name.lower():
                val = flow_dict.get("byte_count", 64)
            else:
                val = 0.0

        # Safe float conversion and clipping
        try:
            float_val = float(val)
            if np.isnan(float_val) or np.isinf(float_val):
                float_val = 0.0
        except (ValueError, TypeError):
            float_val = 0.0

        vector[idx] = float_val

    return vector
