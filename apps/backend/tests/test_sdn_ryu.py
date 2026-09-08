import sys
import os
import socket
import pytest
import httpx

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
repo_dir = os.path.abspath(os.path.join(backend_dir, "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

from sdn.ryu_app import start_standalone_server, _GLOBAL_STATE
from app.domain.containment.ryu_client import RyuSDNClient
from app.domain.containment.service import ContainmentService
from infra.mininet.topology import SentrixTopo, topos


def find_free_port() -> int:
    """Finds an available TCP port on localhost for test server execution."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def ryu_server():
    """Starts the standalone Ryu SDN controller HTTP server for test suite."""
    port = find_free_port()
    server = start_standalone_server(host="127.0.0.1", port=port)
    base_url = f"http://127.0.0.1:{port}"
    yield {"server": server, "base_url": base_url, "port": port}
    server.shutdown()


def test_mininet_topology_structure():
    """Validates Sentrix Mininet custom topology definition and node configurations."""
    topo = SentrixTopo()
    topo.build()

    # Verify switch
    assert "s1" in topo.switches_dict, "Switch s1 must exist in topology"
    assert topo.switches_dict["s1"].get("protocols") == "OpenFlow13"

    # Verify hosts
    expected_hosts = {"h_victim", "h_attacker", "h_client1", "h_client2"}
    assert set(topo.hosts_dict.keys()) == expected_hosts

    # Verify IP and MAC assignments
    assert topo.hosts_dict["h_victim"]["ip"] == "10.0.0.10/24"
    assert topo.hosts_dict["h_victim"]["mac"] == "00:00:00:00:00:10"

    assert topo.hosts_dict["h_attacker"]["ip"] == "10.0.0.45/24"
    assert topo.hosts_dict["h_attacker"]["mac"] == "00:00:00:00:00:45"

    assert topo.hosts_dict["h_client1"]["ip"] == "10.0.0.22/24"
    assert topo.hosts_dict["h_client2"]["ip"] == "10.0.0.33/24"

    # Verify links
    assert len(topo.links_list) == 4
    # Verify topo registry hook for Mininet CLI
    assert "sentrix" in topos
    assert isinstance(topos["sentrix"](), SentrixTopo)


def test_ryu_controller_rest_block_and_unblock(ryu_server):
    """Tests high-level /block, /rules, and /unblock endpoints."""
    base_url = ryu_server["base_url"]
    test_ip = "10.0.0.99"

    with httpx.Client(base_url=base_url) as client:
        # 1. Verify health / switches
        res = client.get("/stats/switches")
        assert res.status_code == 200
        assert 1 in res.json()

        # 2. Block IP
        block_res = client.post("/block", json={"src_ip": test_ip, "dpid": 1, "priority": 65535})
        assert block_res.status_code == 200
        assert block_res.json()["status"] == "blocked"
        assert block_res.json()["src_ip"] == test_ip

        # 3. Verify in rules
        rules_res = client.get("/rules")
        assert rules_res.status_code == 200
        active = [r["src_ip"] for r in rules_res.json()["active_blocks"]]
        assert test_ip in active

        # 4. Unblock IP
        unblock_res = client.post("/unblock", json={"src_ip": test_ip, "dpid": 1})
        assert unblock_res.status_code == 200
        assert unblock_res.json()["status"] == "unblocked"

        # 5. Verify removed from rules
        rules_res = client.get("/rules")
        active = [r["src_ip"] for r in rules_res.json()["active_blocks"]]
        assert test_ip not in active


def test_ryu_sdn_client_integration(ryu_server):
    """Tests that domain RyuSDNClient seamlessly communicates with ryu_app.py."""
    base_url = ryu_server["base_url"]
    client = RyuSDNClient(base_url=base_url, default_dpid=1, timeout_seconds=3.0)

    assert client.is_controller_available() is True

    adversary_ip = "10.0.0.45"

    # Install drop flow
    blocked = client.block_ip(src_ip=adversary_ip)
    assert blocked is True

    # Check switch flow entries
    flows = client.list_switch_flows(dpid=1)
    assert any(f.get("match", {}).get("ipv4_src") == adversary_ip for f in flows)

    # Delete flow (unblock)
    unblocked = client.unblock_ip(src_ip=adversary_ip)
    assert unblocked is True

    flows_after = client.list_switch_flows(dpid=1)
    assert not any(f.get("match", {}).get("ipv4_src") == adversary_ip for f in flows_after)


def test_containment_service_with_active_ryu(ryu_server):
    """Tests that unified ContainmentService prefers Ryu SDN when controller is reachable."""
    base_url = ryu_server["base_url"]
    ryu_client = RyuSDNClient(base_url=base_url, default_dpid=1)
    service = ContainmentService(ryu_client=ryu_client)

    attacker_ip = "10.0.0.123"

    # Apply BLOCK containment
    result = service.apply_containment(src_ip=attacker_ip, action="BLOCK")
    assert result.success is True
    assert result.actuator == "RYU_SDN"
    assert result.action == "BLOCK"
    assert result.details["controller"] == base_url

    # Check active flows in Ryu
    flows = ryu_client.list_switch_flows(dpid=1)
    assert any(f.get("match", {}).get("ipv4_src") == attacker_ip for f in flows)

    # Lift containment
    lift_res = service.lift_containment(src_ip=attacker_ip)
    assert lift_res.success is True
    assert lift_res.details["sdn_unblocked"] is True

    flows_after = ryu_client.list_switch_flows(dpid=1)
    assert not any(f.get("match", {}).get("ipv4_src") == attacker_ip for f in flows_after)
