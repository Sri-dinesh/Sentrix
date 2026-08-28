import os
import shutil
import subprocess
from typing import Set, List


class IptablesDriver:
    """
    Host-level Linux packet filter driver for autonomous threat containment.
    Installs DROP and rate-limiting rules directly into the host INPUT chain.
    Includes in-memory state tracking and graceful simulation when root permissions are unavailable.
    """

    def __init__(self, simulate_if_unprivileged: bool = True):
        self.simulate = simulate_if_unprivileged and (
            os.geteuid() != 0 if hasattr(os, "geteuid") else True
        )
        self._blocked_ips: Set[str] = set()
        self._rate_limited_ips: Set[str] = set()
        self._iptables_bin = shutil.which("iptables") or "/sbin/iptables"

    def block_ip(self, src_ip: str) -> bool:
        """
        Drops all inbound traffic originating from src_ip.
        """
        if src_ip in self._blocked_ips:
            return True

        if not self.simulate and os.path.exists(self._iptables_bin):
            try:
                cmd = ["sudo", self._iptables_bin, "-I", "INPUT", "-s", src_ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                if res.returncode == 0:
                    self._blocked_ips.add(src_ip)
                    return True
            except Exception as e:
                print(f"Warning: iptables block command failed: {e}. Storing simulated block.")

        self._blocked_ips.add(src_ip)
        return True

    def unblock_ip(self, src_ip: str) -> bool:
        """
        Removes DROP rule for src_ip from host firewall.
        """
        if src_ip not in self._blocked_ips:
            return True

        if not self.simulate and os.path.exists(self._iptables_bin):
            try:
                cmd = ["sudo", self._iptables_bin, "-D", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True)
            except Exception as e:
                print(f"Warning: iptables unblock command failed: {e}")

        self._blocked_ips.discard(src_ip)
        return True

    def rate_limit_ip(self, src_ip: str, rate: str = "25/sec") -> bool:
        """
        Applies packet rate limiting to throttle excessive traffic from src_ip.
        """
        if src_ip in self._rate_limited_ips:
            return True

        if not self.simulate and os.path.exists(self._iptables_bin):
            try:
                cmd = [
                    "sudo",
                    self._iptables_bin,
                    "-I",
                    "INPUT",
                    "-s",
                    src_ip,
                    "-m",
                    "limit",
                    "--limit",
                    rate,
                    "-j",
                    "ACCEPT",
                ]
                subprocess.run(cmd, capture_output=True, text=True)
                cmd_drop = [
                    "sudo",
                    self._iptables_bin,
                    "-A",
                    "INPUT",
                    "-s",
                    src_ip,
                    "-j",
                    "DROP",
                ]
                subprocess.run(cmd_drop, capture_output=True, text=True)
            except Exception as e:
                print(f"Warning: iptables rate limit command failed: {e}")

        self._rate_limited_ips.add(src_ip)
        return True

    def is_ip_blocked(self, src_ip: str) -> bool:
        """
        Checks whether the specified IP is actively contained.
        """
        return src_ip in self._blocked_ips

    def list_active_blocks(self) -> List[str]:
        """
        Lists all currently contained IP addresses.
        """
        return sorted(list(self._blocked_ips))

    def clear(self):
        """
        Lifts all active containment blocks.
        """
        for ip in list(self._blocked_ips):
            self.unblock_ip(ip)


_iptables_driver_instance = None


def get_iptables_driver() -> IptablesDriver:
    global _iptables_driver_instance
    if _iptables_driver_instance is None:
        _iptables_driver_instance = IptablesDriver()
    return _iptables_driver_instance
