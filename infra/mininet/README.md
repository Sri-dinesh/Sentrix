# Mininet SDN Simulation

This directory contains Mininet network topology configurations for testing Sentrix's automated containment responses via an external Ryu OpenFlow controller.

## Running the Topology
```bash
sudo mn --custom topology.py --topo sentrix --controller remote,ip=127.0.0.1,port=6653
```
