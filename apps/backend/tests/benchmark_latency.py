import sys
import os
import time
import numpy as np

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.domain.detection.service import get_detection_service
from app.domain.confidence.engine import get_confidence_engine
from app.domain.drift.service import get_drift_service
from ingestion.flow_features import extract_flow_features


def generate_benchmark_flows(num_flows: int = 500):
    """
    Generates synthetic flow dictionaries for high-volume benchmark testing.
    """
    flows = []
    for i in range(num_flows):
        is_attack = i % 5 == 0
        flow = {
            "src_ip": f"10.0.{i % 255}.{(i * 7) % 254 + 1}",
            "dst_ip": "192.168.10.50",
            "src_port": 1024 + (i % 60000),
            "dst_port": 80 if is_attack else 443,
            "protocol": "TCP",
            "packet_count": 500 if is_attack else 12,
            "byte_count": 75000 if is_attack else 1420,
            "duration": 0.85 if is_attack else 0.05,
            "raw_features": {
                "Destination Port": 80 if is_attack else 443,
                "Flow Duration": 850000 if is_attack else 50000,
                "Total Fwd Packets": 250 if is_attack else 6,
                "Total Backward Packets": 250 if is_attack else 6,
                "Flow Bytes/s": 88235.0 if is_attack else 28400.0,
                "Flow Packets/s": 588.2 if is_attack else 240.0,
                "SYN Flag Count": 1 if is_attack else 0,
            },
        }
        flows.append(flow)
    return flows


def run_benchmark():
    print("=" * 60)
    print("       SENTRIX INGESTION & DETECTION INFERENCE BENCHMARK      ")
    print("=" * 60)

    flows = generate_benchmark_flows(500)
    detection_svc = get_detection_service()
    confidence_engine = get_confidence_engine()
    drift_svc = get_drift_service()

    # Warmup
    for f in flows[:20]:
        feat = extract_flow_features(f)
        det = detection_svc.score_flow(feat)
        confidence_engine.calculate(
            anomaly_score=det.anomaly_score,
            classifier_margin=det.classifier_margin,
            drift_score=0.0,
            is_anomalous=det.is_anomalous,
        )

    # Timed benchmark loop
    latencies_ms = []
    start_total = time.perf_counter()

    for flow in flows:
        t0 = time.perf_counter()

        features = extract_flow_features(flow)
        det = detection_svc.score_flow(features)
        drift_svc.observe(det.latent_vector)
        conf = confidence_engine.calculate(
            anomaly_score=det.anomaly_score,
            classifier_margin=det.classifier_margin,
            drift_score=0.04,
            is_anomalous=det.is_anomalous,
        )

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    total_time = time.perf_counter() - start_total
    throughput = len(flows) / total_time

    mean_lat = np.mean(latencies_ms)
    p50_lat = np.percentile(latencies_ms, 50)
    p95_lat = np.percentile(latencies_ms, 95)
    p99_lat = np.percentile(latencies_ms, 99)

    print(f"Total Flows Evaluated: {len(flows)}")
    print(f"Total Benchmark Time:  {total_time:.4f} seconds")
    print(f"Throughput:            {throughput:.2f} flows/second")
    print("-" * 60)
    print(f"Mean Latency:          {mean_lat:.3f} ms")
    print(f"p50 Latency (Median):  {p50_lat:.3f} ms")
    print(f"p95 Latency:           {p95_lat:.3f} ms")
    print(f"p99 Latency:           {p99_lat:.3f} ms")
    print("=" * 60)

    assert throughput >= 100.0, f"Throughput {throughput:.1f} flows/s is below target 100 flows/s"
    assert mean_lat < 5.0, f"Mean latency {mean_lat:.2f} ms exceeds target 5.0 ms"
    print("ALL PERFORMANCE & LATENCY TARGETS SATISFIED (PASSED)")


if __name__ == "__main__":
    run_benchmark()
