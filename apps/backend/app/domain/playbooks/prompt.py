import json
from typing import Dict, Any, Optional

SYSTEM_PROMPT = """You are Sentrix AI, an expert Senior SOC Incident Commander and Autonomous Cyber Defense Specialist.
Your task is to generate a comprehensive, actionable, production-grade Incident Response & Containment Playbook in Markdown format.
You must provide exact, executable shell / firewall commands with the actual IP addresses and ports provided in the telemetry.
Ensure the response is clear, authoritative, and formatted cleanly in standard GitHub-flavored Markdown.
"""


def build_playbook_prompt(
    incident_data: Dict[str, Any],
    detection_data: Dict[str, Any],
    flow_data: Dict[str, Any],
    mitre_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Builds the structured prompt for LLM playbook generation.
    """
    src_ip = flow_data.get("src_ip", "10.0.0.1")
    dst_ip = flow_data.get("dst_ip", "192.168.1.1")
    src_port = flow_data.get("src_port", "0")
    dst_port = flow_data.get("dst_port", "80")
    protocol = flow_data.get("protocol", "TCP")
    packet_count = flow_data.get("packet_count", 0)
    byte_count = flow_data.get("byte_count", 0)
    duration = flow_data.get("duration", 0.0)

    attack_type = detection_data.get("attack_type", "Unknown Anomaly")
    confidence_score = detection_data.get("confidence_score", 0.0)
    anomaly_score = detection_data.get("anomaly_score", 0.0)
    action_taken = incident_data.get("action_taken", "MONITOR")
    status = incident_data.get("status", "open")

    mitre_id = mitre_data.get("id", "T1000") if mitre_data else "T1000"
    mitre_name = (
        mitre_data.get("name", "Unspecified Network Activity")
        if mitre_data
        else "Unspecified Network Activity"
    )
    mitre_tactic = (
        mitre_data.get("tactic", "Impact") if mitre_data else "Impact"
    )
    mitre_description = (
        mitre_data.get("description", "")
        if mitre_data
        else "Network traffic anomaly deviating from baseline distribution."
    )
    mitre_mitigation = (
        mitre_data.get("mitigation", "")
        if mitre_data
        else "Filter offending traffic at network ingress perimeter."
    )

    prompt = f"""Generate an Incident Response & Containment Playbook for the following security event:

### 1. Incident Telemetry
- **Incident Status**: {status.upper()}
- **Response Tier Action**: {action_taken}
- **Detected Threat Classification**: {attack_type}
- **Calibrated Confidence Score**: {confidence_score:.2%}
- **Reconstruction Anomaly Error**: {anomaly_score:.5f}

### 2. Network Flow Evidence
- **Source Endpoint**: `{src_ip}:{src_port}`
- **Destination Endpoint**: `{dst_ip}:{dst_port}`
- **Transport Protocol**: `{protocol}`
- **Flow Volume**: {packet_count} packets, {byte_count} bytes over {duration:.3f}s

### 3. MITRE ATT&CK Context
- **Technique ID**: `{mitre_id}` - **{mitre_name}**
- **Tactic**: `{mitre_tactic}`
- **Context**: {mitre_description}
- **Standard Mitigation**: {mitre_mitigation}

### Required Sections to Generate:
1. **Executive Summary**: Brief narrative describing the threat, the attack vector, and potential impact.
2. **Technical Threat Analysis**: Correlation between the flow telemetry (`{src_ip}` -> `{dst_ip}:{dst_port}`) and MITRE `{mitre_id}` ({mitre_name}).
3. **Immediate Containment Commands**: Exact, copy-pasteable CLI commands to contain `{src_ip}` (using `iptables`, `ufw`, or route nullification).
4. **Forensic Investigation Protocol**: Specific log files, network packet PCAPs, and endpoint artifacts to examine.
5. **Remediation & Hardening**: Long-term defensive countermeasures to prevent recurrence.

Format the output strictly as clean Markdown.
"""
    return prompt
