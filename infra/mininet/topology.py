#!/usr/bin/env python3
"""
Sentrix SDN Simulation Topology
--------------------------------
Custom Mininet topology for evaluating autonomous threat containment via
OpenFlow 1.3 software-defined networking.

Topology Layout:
                  ┌──────────────┐
                  │ Ryu OpenFlow │
                  │  Controller  │
                  └──────┬───────┘
                         │ OpenFlow 1.3 (TCP 6653)
                  ┌──────┴───────┐
                  │  Switch s1   │
                  │  (DPID: 1)   │
                  └──┬──┬──┬──┬──┘
         ┌───────────┘  │  │  └───────────┐
         │              │  │              │
  ┌──────┴──────┐ ┌─────┴──┴────┐ ┌──────┴──────┐
  │  h_victim   │ │  h_client1  │ │ h_attacker  │
  │ 10.0.0.10   │ │ 10.0.0.22   │ │ 10.0.0.45   │
  │ (Server)    │ │ h_client2   │ │ (Adversary) │
  └─────────────┘ │ 10.0.0.33   │ └─────────────┘
                  │ (Clients)   │
                  └─────────────┘

Usage:
  1. Via Mininet Custom Topo CLI:
     sudo mn --custom topology.py --topo sentrix --controller remote,ip=127.0.0.1,port=6653

  2. Standalone execution:
     sudo python3 topology.py --controller-ip 127.0.0.1 --controller-port 6653 --cli
"""

import sys
import argparse
from typing import Dict, Any, List, Tuple

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    from mininet.link import TCLink
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False

    class Topo:  # type: ignore[no-redef]
        """Fallback mock Topo class for non-Mininet development environments."""
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.hosts_dict: Dict[str, Dict[str, Any]] = {}
            self.switches_dict: Dict[str, Dict[str, Any]] = {}
            self.links_list: List[Tuple[str, str, Dict[str, Any]]] = []

        def addSwitch(self, name: str, **opts: Any) -> str:
            self.switches_dict[name] = opts
            return name

        def addHost(self, name: str, **opts: Any) -> str:
            self.hosts_dict[name] = opts
            return name

        def addLink(self, node1: str, node2: str, **opts: Any) -> None:
            self.links_list.append((node1, node2, opts))


class SentrixTopo(Topo):
    """
    Sentrix OpenFlow 1.3 Topology:
    - 1 OpenFlow 1.3 Switch (s1)
    - 1 Target Server / Victim (h_victim, 10.0.0.10)
    - 1 Adversary Host (h_attacker, 10.0.0.45)
    - 2 Legitimate Clients (h_client1: 10.0.0.22, h_client2: 10.0.0.33)
    """

    def build(self, **_opts: Any) -> None:
        # Add OpenFlow 1.3 Switch with datapath ID 1
        s1 = self.addSwitch(
            "s1",
            protocols="OpenFlow13",
            dpid="0000000000000001",
        )

        # Add Target Server (Protected Victim)
        h_victim = self.addHost(
            "h_victim",
            ip="10.0.0.10/24",
            mac="00:00:00:00:00:10",
            defaultRoute="via 10.0.0.1",
        )

        # Add Attacking Host (Source of anomalous flows / attacks)
        h_attacker = self.addHost(
            "h_attacker",
            ip="10.0.0.45/24",
            mac="00:00:00:00:00:45",
            defaultRoute="via 10.0.0.1",
        )

        # Add Legitimate Normal Clients
        h_client1 = self.addHost(
            "h_client1",
            ip="10.0.0.22/24",
            mac="00:00:00:00:00:22",
            defaultRoute="via 10.0.0.1",
        )
        h_client2 = self.addHost(
            "h_client2",
            ip="10.0.0.33/24",
            mac="00:00:00:00:00:33",
            defaultRoute="via 10.0.0.1",
        )

        # Interconnect with realistic QoS parameters
        # Server link: 100Mbps, 2ms latency
        self.addLink(h_victim, s1, bw=100, delay="2ms", loss=0, max_queue_size=1000)
        # Attacker link: 100Mbps, 5ms latency
        self.addLink(h_attacker, s1, bw=100, delay="5ms", loss=0, max_queue_size=1000)
        # Legitimate client links: 100Mbps, 3ms latency
        self.addLink(h_client1, s1, bw=100, delay="3ms", loss=0, max_queue_size=1000)
        self.addLink(h_client2, s1, bw=100, delay="3ms", loss=0, max_queue_size=1000)


# Dictionary export required for Mininet CLI custom topology loader (`--custom topology.py --topo sentrix`)
topos = {"sentrix": (lambda: SentrixTopo())}


def run_topology(
    controller_ip: str = "127.0.0.1",
    controller_port: int = 6653,
    start_cli: bool = True,
    test_ping: bool = False,
) -> None:
    """Instantiates and launches the Mininet network."""
    if not MININET_AVAILABLE:
        print("[!] Mininet is not installed in the active Python environment.")
        print("[*] Printing Sentrix Topology Definition:")
        topo = SentrixTopo()
        topo.build()
        print(f"  Switches ({len(topo.switches_dict)}): {list(topo.switches_dict.keys())}")
        for host, meta in topo.hosts_dict.items():
            print(f"  Host: {host:<12} IP: {meta.get('ip')}  MAC: {meta.get('mac')}")
        print(f"  Links ({len(topo.links_list)}):")
        for src, dst, opts in topo.links_list:
            print(f"    {src} <---> {dst} (bw={opts.get('bw')}M, delay={opts.get('delay')})")
        print("\n[*] To run on a Linux Mininet host:")
        print(f"    sudo python3 infra/mininet/topology.py --controller-ip {controller_ip} --controller-port {controller_port} --cli")
        return

    setLogLevel("info")
    info(f"[*] Initializing Sentrix Mininet Topology with Ryu Controller ({controller_ip}:{controller_port})...\n")

    topo = SentrixTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=True,
    )

    info(f"[*] Connecting to remote OpenFlow controller {controller_ip}:{controller_port}...\n")
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    net.start()
    info("[+] Mininet network started successfully!\n")

    if test_ping:
        info("[*] Running connectivity verification across all nodes...\n")
        net.pingAll()

    if start_cli:
        info("[*] Entering Mininet CLI. Type 'exit' to terminate.\n")
        CLI(net)

    info("[*] Stopping Mininet network...\n")
    net.stop()
    info("[+] Network stopped.\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentrix Mininet SDN Simulation Topology")
    parser.add_argument(
        "--controller-ip",
        type=str,
        default="127.0.0.1",
        help="IP address of the remote Ryu OpenFlow controller (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--controller-port",
        type=int,
        default=6653,
        help="OpenFlow listen port of the remote Ryu controller (default: 6653)",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        default=True,
        help="Launch interactive Mininet CLI after starting network (default: True)",
    )
    parser.add_argument(
        "--test-ping",
        action="store_true",
        default=False,
        help="Execute pingAll to test initial connectivity before CLI",
    )
    parser.add_argument(
        "--dump-topo",
        action="store_true",
        default=False,
        help="Print topology node and link specifications and exit",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.dump_topo:
        topo = SentrixTopo()
        topo.build()
        print(f"Sentrix Topology: {len(topo.hosts_dict)} hosts, {len(topo.switches_dict)} switches, {len(topo.links_list)} links.")
        sys.exit(0)
    run_topology(
        controller_ip=args.controller_ip,
        controller_port=args.controller_port,
        start_cli=args.cli,
        test_ping=args.test_ping,
    )
