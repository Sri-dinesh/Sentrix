import os
import json
import httpx
from typing import Optional, Dict, Any
from app.core.config import settings


class OllamaClient:
    """
    Client for interacting with local Ollama LLM instance.
    Supports asynchronous and synchronous prompt generation with graceful fallback.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 45.0,
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout_seconds

    async def generate_async(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
    ) -> str:
        """
        Asynchronously sends prompt to Ollama /api/generate endpoint.
        """
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("response", "").strip()
                else:
                    print(
                        f"Ollama returned HTTP {response.status_code}: {response.text}"
                    )
        except Exception as e:
            print(f"Ollama connection error: {e}. Utilizing fallback synthesizer.")

        return self._generate_fallback_playbook(prompt)

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
    ) -> str:
        """
        Synchronous version for execution in Celery worker threads.
        """
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("response", "").strip()
                else:
                    print(
                        f"Ollama returned HTTP {response.status_code}: {response.text}"
                    )
        except Exception as e:
            print(f"Ollama connection error: {e}. Utilizing fallback synthesizer.")

        return self._generate_fallback_playbook(prompt)

    def _generate_fallback_playbook(self, prompt: str) -> str:
        """
        Deterministic, structured fallback playbook used when Ollama service is unavailable.
        """
        return """# Incident Response & Remediation Playbook

## 1. Executive Summary
An automated security anomaly was detected by the Sentrix Real-Time Detection Engine. Immediate containment protocols have been evaluated and staged for analyst execution.

## 2. Threat Analysis & MITRE ATT&CK Mapping
- **Classification**: Network Intrusion Anomaly / Targeted Threat Traffic
- **Severity**: Elevated (Calibrated Confidence Metric)
- **Impact Analysis**: Potential unauthorized data exfiltration, lateral network exploration, or resource exhaustion attack pattern.

## 3. Immediate Containment Actions
Execute the following commands on edge security appliances or host firewalls:

```bash
# 1. Block offending source IP at host perimeter
sudo iptables -I INPUT -s <OFFENDING_SRC_IP> -j DROP

# 2. Terminate active socket states
sudo ss -K dst <OFFENDING_SRC_IP>

# 3. Log containment action to audit log
logger -t SENTRIX_CONTAINMENT "Blocked IP <OFFENDING_SRC_IP> following confidence-calibrated alert"
```

## 4. Forensic Investigation Steps
1. **Pcap Deep Inspection**: Review full bidirectional packet captures around the detection timestamp.
2. **Endpoint Cross-Correlation**: Check authentication logs (`/var/log/auth.log` or syslog) on destination hosts for failed attempts.
3. **Lateral Movement Review**: Monitor internal subnets for secondary port-scan signatures originating from the affected target.

## 5. Long-Term Hardening Recommendations
- Implement granular egress/ingress network access control lists (ACLs).
- Apply rate limiting on external-facing service ports.
- Rotate credentials and verify service account permissions across impacted endpoints.
"""


_ollama_client_instance: Optional[OllamaClient] = None


def get_ollama_client() -> OllamaClient:
    global _ollama_client_instance
    if _ollama_client_instance is None:
        _ollama_client_instance = OllamaClient()
    return _ollama_client_instance
