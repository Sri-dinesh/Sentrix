import httpx
from typing import Optional, Dict, Any, List
from app.core.config import settings


class RyuSDNClient:
    """
    Client for interacting with Ryu OpenFlow 1.3 SDN Controller REST API.
    Installs, modifies, and deletes flow table entries for autonomous traffic containment.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_dpid: int = 1,
        timeout_seconds: float = 5.0,
    ):
        self.base_url = (base_url or settings.RYU_API_URL).rstrip("/")
        self.default_dpid = default_dpid
        self.timeout = timeout_seconds

    def is_controller_available(self) -> bool:
        """
        Checks if the Ryu SDN controller REST service is active and responsive.
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/stats/switches")
                return res.status_code == 200
        except Exception:
            return False

    def block_ip(
        self,
        src_ip: str,
        dpid: Optional[int] = None,
        priority: int = 65535,
    ) -> bool:
        """
        Installs an OpenFlow DROP rule on the switch for the specified source IP.
        Matching traffic is immediately dropped at line rate with no forwarding action.
        """
        target_dpid = dpid or self.default_dpid
        payload = {
            "dpid": target_dpid,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 3600,  # 1 hour lease
            "hard_timeout": 86400,  # 24 hours max
            "priority": priority,
            "flags": 1,
            "match": {
                "eth_type": 2048,  # IPv4
                "ipv4_src": src_ip,
            },
            "actions": [],  # Empty action list = DROP in OpenFlow
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(
                    f"{self.base_url}/stats/flowentry/add",
                    json=payload,
                )
                return res.status_code == 200
        except Exception as e:
            print(f"Ryu SDN block flow error for {src_ip}: {e}")
            return False

    def rate_limit_ip(
        self,
        src_ip: str,
        dpid: Optional[int] = None,
        meter_id: int = 1,
        priority: int = 60000,
    ) -> bool:
        """
        Installs an OpenFlow meter rule to throttle bandwidth from the offending source IP.
        """
        target_dpid = dpid or self.default_dpid
        payload = {
            "dpid": target_dpid,
            "cookie": 2,
            "table_id": 0,
            "idle_timeout": 1800,
            "priority": priority,
            "match": {
                "eth_type": 2048,
                "ipv4_src": src_ip,
            },
            "actions": [
                {"type": "METER", "meter_id": meter_id},
                {"type": "OUTPUT", "port": "NORMAL"},
            ],
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(
                    f"{self.base_url}/stats/flowentry/add",
                    json=payload,
                )
                return res.status_code == 200
        except Exception as e:
            print(f"Ryu SDN rate limit error for {src_ip}: {e}")
            return False

    def unblock_ip(
        self,
        src_ip: str,
        dpid: Optional[int] = None,
    ) -> bool:
        """
        Removes the OpenFlow blocking rule for the source IP from the switch.
        """
        target_dpid = dpid or self.default_dpid
        payload = {
            "dpid": target_dpid,
            "table_id": 0,
            "match": {
                "eth_type": 2048,
                "ipv4_src": src_ip,
            },
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(
                    f"{self.base_url}/stats/flowentry/delete_strict",
                    json=payload,
                )
                return res.status_code == 200
        except Exception as e:
            print(f"Ryu SDN unblock flow error for {src_ip}: {e}")
            return False

    def list_switch_flows(self, dpid: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Lists active flow entries on the switch.
        """
        target_dpid = dpid or self.default_dpid
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/stats/flow/{target_dpid}")
                if res.status_code == 200:
                    data = res.json()
                    return data.get(str(target_dpid), [])
        except Exception as e:
            print(f"Ryu SDN list flows error: {e}")
        return []


_ryu_client_instance: Optional[RyuSDNClient] = None


def get_ryu_client() -> RyuSDNClient:
    global _ryu_client_instance
    if _ryu_client_instance is None:
        _ryu_client_instance = RyuSDNClient()
    return _ryu_client_instance
