#!/usr/bin/env python3
"""
Sentrix Real-Time Demo Traffic Replay Engine
--------------------------------------------
Sequentially feeds the curated 20-flow demo trajectory through the full live Sentrix pipeline:
Ingestion -> PyTorch Autoencoder Anomaly Scoring -> XGBoost Classifier Margin ->
Two-Sample KS Drift Monitoring -> Multi-Signal Confidence Tiering ->
Autonomous Response (Ryu SDN / iptables) -> MITRE ATT&CK Mapping -> Ollama AI Playbook.

Usage:
  python apps/backend/ml/demo_replay.py [--interval 0.5] [--loop]
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, List

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
repo_dir = os.path.abspath(os.path.join(backend_dir, "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

from app.db.session import SessionLocal
from ingestion.publisher import ingest_flow

DEFAULT_SLICE_PATH = os.path.join(repo_dir, "datasets/demo/demo_traffic_slice.json")

# ANSI Color Codes for SOC Terminal Presentation
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_GREEN = "\033[92m"
C_MAGENTA = "\033[95m"
C_BLUE = "\033[94m"
C_GRAY = "\033[90m"


def print_banner():
    print(f"\n{C_CYAN}{C_BOLD}" + "=" * 78)
    print("      SENTRIX AUTONOMOUS THREAT CONTAINMENT — LIVE DEMO REPLAY ENGINE")
    print("=" * 78 + f"{C_RESET}\n")


def format_tier(tier: Any) -> str:
    val = tier.value if hasattr(tier, "value") else str(tier)
    if val == "HIGH":
        return f"{C_RED}{C_BOLD}[HIGH — AUTO BLOCK]{C_RESET}"
    elif val == "MEDIUM":
        return f"{C_YELLOW}{C_BOLD}[MEDIUM — INVESTIGATE]{C_RESET}"
    return f"{C_GREEN}[LOW — MONITOR]{C_RESET}"


def format_action(action: str) -> str:
    if action == "BLOCK":
        return f"{C_RED}{C_BOLD}BLOCK (Line-Rate Drop){C_RESET}"
    elif action == "RATE_LIMIT":
        return f"{C_YELLOW}RATE_LIMIT (Throttle){C_RESET}"
    return f"{C_GREEN}MONITOR (Pass-Through){C_RESET}"


def run_replay(
    slice_path: str = DEFAULT_SLICE_PATH,
    interval: float = 0.5,
    loop: bool = False,
    auto_contain: bool = True,
    generate_playbook: bool = True,
):
    if not os.path.exists(slice_path):
        print(f"{C_RED}Error: Demo slice not found at {slice_path}{C_RESET}")
        sys.exit(1)

    with open(slice_path, "r", encoding="utf-8") as f:
        flows: List[Dict[str, Any]] = json.load(f)

    print_banner()
    print(f"[*] Loaded {len(flows)} curated demo flow records from {os.path.basename(slice_path)}")
    print(f"[*] Step interval: {interval}s | Loop mode: {loop} | Autonomous containment: {auto_contain}\n")

    iteration = 0
    while True:
        iteration += 1
        if loop and iteration > 1:
            print(f"\n{C_MAGENTA}{C_BOLD}--- Starting Replay Iteration #{iteration} ---{C_RESET}\n")

        # Connect to DB or create fallback in-memory SQLite database
        from sqlalchemy import text, create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        from app.models.base import Base
        from app.models.mitre import MitreTechnique
        from app.repositories import user_repository, settings_repository

        db = None
        try:
            db_candidate = SessionLocal()
            db_candidate.execute(text("SELECT 1"))
            db = db_candidate
        except Exception:
            # Fallback to in-memory SQLite
            mem_engine = create_engine(
                "sqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
            Base.metadata.create_all(mem_engine)
            MemSession = sessionmaker(autocommit=False, autoflush=False, bind=mem_engine)
            db = MemSession()

            # Seed basic MITRE techniques and settings in fallback
            techniques = [
                MitreTechnique(id="T1498", name="Network Denial of Service", tactic="Impact", description="DoS attack"),
                MitreTechnique(id="T1110", name="Brute Force", tactic="Credential Access", description="Brute force credentials"),
                MitreTechnique(id="T1595.001", name="Port Scanning", tactic="Reconnaissance", description="Port scanning"),
                MitreTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access", description="Web application exploit"),
            ]
            for t in techniques:
                db.add(t)
            settings_repository.get_settings(db)
            db.commit()

        stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "BLOCK": 0, "RATE_LIMIT": 0, "MONITOR": 0}

        try:
            for idx, item in enumerate(flows, 1):
                phase = item.get("phase", "Traffic Stream")
                desc = item.get("description", "")
                src_ip = item.get("src_ip", "10.0.0.1")
                dst_ip = item.get("dst_ip", "10.0.0.10")
                dst_port = item.get("dst_port", 80)
                proto = item.get("protocol", "TCP")

                print(f"{C_BOLD}Flow #{idx:02d} | Phase: {C_MAGENTA}{phase}{C_RESET} | {C_GRAY}{desc}{C_RESET}")
                print(f"  Connection : {C_CYAN}{src_ip}{C_RESET} -> {C_BLUE}{dst_ip}:{dst_port} ({proto}){C_RESET}")

                start_t = time.time()
                result = ingest_flow(
                    item,
                    db=db,
                    auto_contain=auto_contain,
                    generate_playbook=generate_playbook,
                )
                elapsed_ms = (time.time() - start_t) * 1000.0

                det = result.get("detection")
                conf = result.get("confidence")
                contain = result.get("containment")
                inc = result.get("incident")

                tier_val = conf.tier.value if (conf and hasattr(conf.tier, "value")) else (str(conf.tier) if conf else "LOW")
                action_val = contain.action if contain else "MONITOR"
                stats[tier_val] = stats.get(tier_val, 0) + 1
                stats[action_val] = stats.get(action_val, 0) + 1

                # Telemetry printout
                tier_str = format_tier(tier_val)
                action_str = format_action(action_val)
                anom_str = f"MSE={det.anomaly_score:.4f}" if (det and det.anomaly_score is not None) else "N/A"
                clf_str = f"Label={det.attack_type or 'BENIGN'} (margin={det.classifier_margin or 0.0:.2f})" if det else "N/A"
                
                if conf:
                    comps = conf.breakdown.get("components", {})
                    primary = "anomaly" if comps.get("anomaly_contribution", 0) >= comps.get("classifier_contribution", 0) else "classifier"
                    conf_str = f"Conf={conf.score:.2f} (driver: {primary})"
                else:
                    conf_str = "Conf=N/A"

                print(f"  Telemetry  : {tier_str} | {action_str} | {C_GRAY}{anom_str} | {clf_str} | {conf_str}{C_RESET}")

                if inc and inc.mitre_technique_id:
                    tech_name = inc.mitre_technique.name if inc.mitre_technique else "Unknown"
                    print(f"  MITRE Tag  : {C_YELLOW}{inc.mitre_technique_id}{C_RESET} — {tech_name}")

                if contain and contain.action == "BLOCK":
                    print(f"  {C_RED}[!] SDN RULE INSTALLED: Dropping all line-rate packets from {src_ip} on Switch s1{C_RESET}")
                elif contain and contain.action == "RATE_LIMIT":
                    print(f"  {C_YELLOW}[!] RATE LIMIT APPLIED: Throttled ingress bandwidth for {src_ip}{C_RESET}")

                print(f"  Processing : {C_GRAY}{elapsed_ms:.2f} ms latency{C_RESET}\n")

                if interval > 0:
                    time.sleep(interval)

            print(f"{C_CYAN}{C_BOLD}" + "=" * 78)
            print("                        DEMO REPLAY SUMMARY")
            print("=" * 78 + f"{C_RESET}")
            print(f"  Total Ingested Flows     : {len(flows)}")
            print(f"  HIGH Tier (Auto-Block)   : {C_RED}{stats['HIGH']}{C_RESET}")
            print(f"  MEDIUM Tier (Investigate): {C_YELLOW}{stats['MEDIUM']}{C_RESET}")
            print(f"  LOW Tier (Monitor)       : {C_GREEN}{stats['LOW']}{C_RESET}")
            print(f"  Line-Rate Blocks Applied : {C_RED}{stats['BLOCK']}{C_RESET}")
            print(f"  Rate Limits Enforced     : {C_YELLOW}{stats['RATE_LIMIT']}{C_RESET}")
            print(f"{C_CYAN}" + "=" * 78 + f"{C_RESET}\n")

        finally:
            db.close()

        if not loop:
            break


def main():
    parser = argparse.ArgumentParser(description="Sentrix SOC Demo Traffic Replay Engine")
    parser.add_argument(
        "--file",
        type=str,
        default=DEFAULT_SLICE_PATH,
        help="Path to curated demo traffic slice JSON (default: datasets/demo/demo_traffic_slice.json)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.3,
        help="Interval between flows in seconds (default: 0.3s)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Loop continuously through demo slice",
    )
    parser.add_argument(
        "--no-contain",
        action="store_true",
        help="Disable autonomous containment actuation",
    )
    parser.add_argument(
        "--playbook",
        action="store_true",
        help="Trigger LLM playbook generation for incidents (requires Ollama / Celery)",
    )

    args = parser.parse_args()
    run_replay(
        slice_path=args.file,
        interval=args.interval,
        loop=args.loop,
        auto_contain=not args.no_contain,
        generate_playbook=args.playbook,
    )


if __name__ == "__main__":
    main()
