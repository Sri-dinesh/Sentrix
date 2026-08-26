import os
import time
import uuid
from datetime import datetime, timezone
import pandas as pd
from typing import Generator, Dict, Any, Optional

DATASETS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../datasets")
)


def replay_dataset_csv(
    csv_path: Optional[str] = None,
    delay_seconds: float = 0.0,
    max_flows: Optional[int] = None,
) -> Generator[Dict[str, Any], None, None]:
    """
    Generator that replays flow records from dataset CSVs, simulating live network traffic arrival.
    """
    if not csv_path:
        csv_path = os.path.join(DATASETS_DIR, "CICIDS2017/CICIDS2017_sample.csv")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Replay dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    count = 0

    # Deterministic sample IPs based on attack label
    ip_map = {
        "BENIGN": ("192.168.1.105", "172.217.16.206"),
        "DoS Hulk": ("10.0.0.45", "192.168.10.50"),
        "DDoS": ("10.0.0.99", "192.168.10.50"),
        "PortScan": ("10.0.0.77", "192.168.10.50"),
        "SSH-Patator": ("10.0.0.22", "192.168.10.22"),
        "Web Attack - SQL Injection": ("10.0.0.88", "192.168.10.80"),
        "Bot": ("10.0.0.66", "192.168.10.66"),
    }

    for idx, row in df.iterrows():
        if max_flows and count >= max_flows:
            break

        label = str(row.get("Label", "BENIGN")).strip()
        default_src, default_dst = ip_map.get(
            label, (f"10.0.0.{100 + (idx % 100)}", "192.168.10.50")
        )

        dst_port = int(row.get("Destination Port", 80))
        duration = float(row.get("Flow Duration", 1000.0)) / 1000.0
        fwd_pkts = int(row.get("Total Fwd Packets", 1))
        bwd_pkts = int(row.get("Total Backward Packets", 1))
        fwd_len = float(row.get("Total Length of Fwd Packets", 64))
        bwd_len = float(row.get("Total Length of Bwd Packets", 64))

        raw_dict = row.to_dict()

        flow_record = {
            "id": uuid.uuid4(),
            "captured_at": datetime.now(timezone.utc),
            "src_ip": default_src,
            "dst_ip": default_dst,
            "src_port": int(49152 + (idx % 16000)),
            "dst_port": dst_port,
            "protocol": "TCP" if dst_port != 53 else "UDP",
            "packet_count": fwd_pkts + bwd_pkts,
            "byte_count": int(fwd_len + bwd_len),
            "duration": duration,
            "raw_features": raw_dict,
            "actual_label": label,
        }

        yield flow_record
        count += 1

        if delay_seconds > 0:
            time.sleep(delay_seconds)
