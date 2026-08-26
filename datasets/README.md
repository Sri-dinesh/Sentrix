# Sentrix Datasets

This directory contains the benchmark network intrusion detection datasets and MITRE ATT&CK taxonomies used for model training, threshold calibration, and evaluation.

## Datasets Staged

1. **NSL-KDD**:
   - `KDDTrain+.csv`: 125,973 records across 23 attack subcategories and `normal`.
   - `KDDTest+.csv`: 22,543 held-out test evaluation records with novel attack variations.
   - Features: 41 connection features (duration, protocol_type, service, flag, src_bytes, dst_bytes, count, srv_count, etc.).

2. **CICIDS2017**:
   - `CICIDS2017_sample.csv`: 25,000 bidirectional flow records with 71 numeric network flow features.
   - Attack categories included: `BENIGN`, `DoS Hulk`, `DDoS`, `PortScan`, `SSH-Patator`, `Web Attack - SQL Injection`, `Bot`.

3. **MITRE ATT&CK Mapping**:
   - `mitre/attack_technique_map.json`: Direct mapping between dataset attack categories and MITRE ATT&CK technique IDs (`T1498`, `T1595`, `T1110`, `T1190`, `T1059.007`, `T1584.005`, `T1078`, `T1068`, `T1000`).

4. **Demonstration Replays**:
   - `demo/`: Curated time-series traces for live streaming simulation and SDN actuation tests.
