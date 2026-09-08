# Sentrix Mininet SDN Simulation & Runbook

This directory provides the Software-Defined Networking (SDN) simulation infrastructure for Sentrix. It defines a custom OpenFlow 1.3 network topology using Mininet, connected to an external Ryu controller (`apps/backend/sdn/ryu_app.py`) for automated, line-rate threat containment.

---

## Topology Architecture

```text
                  ┌────────────────────────┐
                  │ Ryu OpenFlow Controller│
                  │  (REST API: port 8080) │
                  │  (OpenFlow: port 6653) │
                  └───────────┬────────────┘
                              │ OpenFlow 1.3 Control Channel
                  ┌───────────┴────────────┐
                  │      Switch s1         │
                  │      (DPID: 1)         │
                  └─┬────┬───────────┬───┬─┘
         ┌──────────┘    │           │   └──────────┐
         │ (port 1)      │ (port 2)  │ (port 3)     │ (port 4)
  ┌──────┴──────┐ ┌──────┴──────┐ ┌──┴──────────┐ ┌─┴───────────┐
  │  h_victim   │ │  h_client1  │ │  h_client2  │ │ h_attacker  │
  │ 10.0.0.10   │ │ 10.0.0.22   │ │ 10.0.0.33   │ │ 10.0.0.45   │
  │ Web/App Svr │ │ Workstation │ │ Customer    │ │ Adversary   │
  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

### Network Allocations

| Host / Node | IP Address | MAC Address | Switch Port | Role | Link QoS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `s1` | N/A | N/A | N/A | OpenFlow 1.3 Switch | DPID: `0000000000000001` |
| `h_victim` | `10.0.0.10/24` | `00:00:00:00:00:10` | 1 | Protected Server | 100 Mbps, 2ms delay |
| `h_client1` | `10.0.0.22/24` | `00:00:00:00:00:22` | 2 | Legitimate Client 1 | 100 Mbps, 3ms delay |
| `h_client2` | `10.0.0.33/24` | `00:00:00:00:00:33` | 3 | Legitimate Client 2 | 100 Mbps, 3ms delay |
| `h_attacker` | `10.0.0.45/24` | `00:00:00:00:00:45` | 4 | Threat Source | 100 Mbps, 5ms delay |

---

## Prerequisites

To run live Mininet with kernel Open vSwitch (OVS):
- **Linux OS** (Ubuntu 22.04+, Debian 12+, or Arch Linux with kernel headers)
- **Mininet**: `sudo apt install mininet openvswitch-switch` (or package manager equivalent)
- **Ryu Manager**: Installed in Python environment or run via Docker container

---

## Step-by-Step Runbook

### Step 1: Launch Ryu OpenFlow Controller
Start the Sentrix Ryu controller application with OpenFlow listening on port `6653` and REST API on port `8080`:

```bash
ryu-manager apps/backend/sdn/ryu_app.py --ofp-tcp-listen-port 6653
```

*(Alternatively, for local dev/testing without Ryu installed, run the standalone controller:*
```bash
python3 apps/backend/sdn/ryu_app.py --port 8080
```
*)*

---

### Step 2: Launch Mininet Topology
In a separate terminal with root privileges:

```bash
sudo python3 infra/mininet/topology.py --controller-ip 127.0.0.1 --controller-port 6653 --cli
```

Or using Mininet's standard CLI runner:
```bash
sudo mn --custom infra/mininet/topology.py --topo sentrix --controller remote,ip=127.0.0.1,port=6653
```

---

### Step 3: Verify L2 Forwarding Connectivity
In the Mininet CLI prompt (`mininet>`):

```bash
mininet> pingall
```
All hosts should be able to ping each other once Ryu establishes L2 learning table entries.

Verify client access to victim server:
```bash
mininet> h_client1 ping -c 3 h_victim
mininet> h_attacker ping -c 3 h_victim
```
*(Both commands show 0% packet loss).*

---

### Step 4: Verify OpenFlow 1.3 Flow Entries
Inspect the switch's hardware flow tables:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

### Step 5: Execute Autonomous Containment
Simulate Sentrix detection triggering an SDN containment action against the adversary (`10.0.0.45`):

```bash
curl -X POST http://127.0.0.1:8080/block \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "10.0.0.45", "dpid": 1}'
```

Verify containment in Mininet CLI:
```bash
mininet> h_attacker ping -c 3 h_victim
# Output: 100% packet loss (traffic dropped at line rate by switch s1)

mininet> h_client1 ping -c 3 h_victim
# Output: 0% packet loss (normal corporate traffic remains completely unaffected!)
```

Check active rules from controller:
```bash
curl http://127.0.0.1:8080/rules
```

---

### Step 6: Lift Containment (Analyst False Positive / Resolution)
Once the threat is resolved or identified as a false positive:

```bash
curl -X POST http://127.0.0.1:8080/unblock \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "10.0.0.45", "dpid": 1}'
```

Verify connectivity is immediately restored:
```bash
mininet> h_attacker ping -c 3 h_victim
# Output: 0% packet loss (traffic permitted once more)
```
