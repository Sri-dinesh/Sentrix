from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from app.domain.containment.ryu_client import RyuSDNClient, get_ryu_client
from app.domain.containment.iptables_driver import IptablesDriver, get_iptables_driver


@dataclass
class ContainmentResult:
    src_ip: str
    action: str  # "BLOCK", "RATE_LIMIT", "UNBLOCK", "MONITOR"
    actuator: str  # "RYU_SDN", "IPTABLES", "NONE"
    success: bool
    applied_at: datetime
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "action": self.action,
            "actuator": self.actuator,
            "success": self.success,
            "applied_at": self.applied_at.isoformat(),
            "details": self.details,
        }


class ContainmentService:
    """
    Unified Orchestrator for Autonomous Threat Containment.
    Executes response actions across programmable SDN switches (Ryu OpenFlow)
    with seamless automatic fallback to host firewall (iptables).
    """

    def __init__(
        self,
        ryu_client: Optional[RyuSDNClient] = None,
        iptables_driver: Optional[IptablesDriver] = None,
    ):
        self.ryu = ryu_client or get_ryu_client()
        self.iptables = iptables_driver or get_iptables_driver()
        self._history: List[ContainmentResult] = []

    def apply_containment(
        self,
        src_ip: str,
        action: str,  # "BLOCK", "RATE_LIMIT", "MONITOR"
        dpid: Optional[int] = None,
    ) -> ContainmentResult:
        """
        Applies confidence-calibrated containment action to the offending IP address.
        """
        now = datetime.now(timezone.utc)

        if action == "MONITOR" or not action:
            res = ContainmentResult(
                src_ip=src_ip,
                action="MONITOR",
                actuator="NONE",
                success=True,
                applied_at=now,
                details={"message": "No active containment triggered. Traffic monitored."},
            )
            self._history.append(res)
            return res

        # Attempt Ryu OpenFlow SDN actuation first
        if self.ryu.is_controller_available():
            sdn_success = False
            if action == "BLOCK":
                sdn_success = self.ryu.block_ip(src_ip, dpid=dpid)
            elif action == "RATE_LIMIT":
                sdn_success = self.ryu.rate_limit_ip(src_ip, dpid=dpid)

            if sdn_success:
                # Also mirror into host driver state
                if action == "BLOCK":
                    self.iptables.block_ip(src_ip)
                elif action == "RATE_LIMIT":
                    self.iptables.rate_limit_ip(src_ip)

                res = ContainmentResult(
                    src_ip=src_ip,
                    action=action,
                    actuator="RYU_SDN",
                    success=True,
                    applied_at=now,
                    details={
                        "dpid": dpid or self.ryu.default_dpid,
                        "controller": self.ryu.base_url,
                        "method": "OpenFlow 1.3 FlowTable Modification",
                    },
                )
                self._history.append(res)
                return res

        # Fallback to host iptables driver
        iptables_success = False
        if action == "BLOCK":
            iptables_success = self.iptables.block_ip(src_ip)
        elif action == "RATE_LIMIT":
            iptables_success = self.iptables.rate_limit_ip(src_ip)

        res = ContainmentResult(
            src_ip=src_ip,
            action=action,
            actuator="IPTABLES",
            success=iptables_success,
            applied_at=now,
            details={
                "method": "Linux Netfilter/iptables INPUT rule",
                "simulated": self.iptables.simulate,
            },
        )
        self._history.append(res)
        return res

    def lift_containment(
        self,
        src_ip: str,
        dpid: Optional[int] = None,
    ) -> ContainmentResult:
        """
        Lifts containment rules for src_ip across all actuators (SDN & host).
        """
        now = datetime.now(timezone.utc)

        # Unblock in Ryu if controller is live
        sdn_cleared = False
        if self.ryu.is_controller_available():
            sdn_cleared = self.ryu.unblock_ip(src_ip, dpid=dpid)

        # Unblock in iptables
        iptables_cleared = self.iptables.unblock_ip(src_ip)

        res = ContainmentResult(
            src_ip=src_ip,
            action="UNBLOCK",
            actuator="ALL",
            success=iptables_cleared or sdn_cleared,
            applied_at=now,
            details={
                "sdn_unblocked": sdn_cleared,
                "iptables_unblocked": iptables_cleared,
            },
        )
        self._history.append(res)
        return res

    def list_active_contained_ips(self) -> List[str]:
        """
        Lists all currently contained source IP addresses.
        """
        return self.iptables.list_active_blocks()

    def get_history(self, limit: int = 50) -> List[ContainmentResult]:
        return self._history[-limit:]


_containment_service_instance: Optional[ContainmentService] = None


def get_containment_service() -> ContainmentService:
    global _containment_service_instance
    if _containment_service_instance is None:
        _containment_service_instance = ContainmentService()
    return _containment_service_instance
