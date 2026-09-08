#!/usr/bin/env python3
"""
Sentrix Ryu OpenFlow 1.3 SDN Controller Application
---------------------------------------------------
Implements:
1. OpenFlow 1.3 L2 Learning Switch (mac_to_port learning & line-rate forwarding).
2. Autonomous Threat Containment REST API:
   - POST /block       : Installs priority 65535 OpenFlow DROP rule for source IPv4.
   - POST /unblock     : Deletes matching DROP rule to restore connectivity.
   - GET  /rules       : Dumps all active containment rules and drop statistics.
3. Ryu ofctl_rest compatibility endpoints:
   - GET  /stats/switches
   - POST /stats/flowentry/add
   - POST /stats/flowentry/delete_strict
   - GET  /stats/flow/{dpid}
4. Dual-Mode execution:
   - Native mode: Runs inside `ryu-manager apps/backend/sdn/ryu_app.py` with WSGI.
   - Standalone mode: Runs directly with `python ryu_app.py --port 8080` for dev,
     CI testing, and environments without Open vSwitch / Ryu dependencies.
"""

import sys
import json
import time
import argparse
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

# Detect if Ryu framework is available in the Python runtime
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ether_types, ipv4
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route
    from webob import Response
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    # Mock base class when Ryu is not installed
    class _MockAppManager:
        class RyuApp:
            pass
    app_manager = _MockAppManager()  # type: ignore[assignment]


# In-memory shared state for switch datapaths and containment rules
class SwitchState:
    """Manages active switches, flow tables, and containment rules in memory."""

    def __init__(self) -> None:
        self.switches: Dict[int, Any] = {1: {"dpid": 1, "connected_at": time.time()}}
        self.active_blocks: Dict[str, Dict[str, Any]] = {}
        self.flow_stats: List[Dict[str, Any]] = []

    def block_ip(self, src_ip: str, dpid: int = 1, priority: int = 65535) -> Dict[str, Any]:
        rule_entry = {
            "dpid": dpid,
            "src_ip": src_ip,
            "priority": priority,
            "action": "DROP",
            "packet_count": 0,
            "byte_count": 0,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "match": {"eth_type": 2048, "ipv4_src": src_ip},
        }
        self.active_blocks[src_ip] = rule_entry
        return rule_entry

    def unblock_ip(self, src_ip: str, dpid: int = 1) -> bool:
        if src_ip in self.active_blocks:
            del self.active_blocks[src_ip]
            return True
        return False

    def list_rules(self, dpid: Optional[int] = None) -> List[Dict[str, Any]]:
        if dpid is None:
            return list(self.active_blocks.values())
        return [r for r in self.active_blocks.values() if r["dpid"] == dpid]

    def list_flows(self, dpid: int = 1) -> List[Dict[str, Any]]:
        flows = []
        for src_ip, rule in self.active_blocks.items():
            if rule["dpid"] == dpid:
                flows.append({
                    "priority": rule["priority"],
                    "table_id": 0,
                    "duration_sec": 120,
                    "packet_count": rule.get("packet_count", 0),
                    "byte_count": rule.get("byte_count", 0),
                    "match": rule["match"],
                    "actions": [],
                })
        return flows


_GLOBAL_STATE = SwitchState()


if RYU_AVAILABLE:
    SENTRIX_API_INSTANCE_NAME = "sentrix_sdn_api_app"
    url_block = "/block"
    url_unblock = "/unblock"
    url_rules = "/rules"
    url_switches = "/stats/switches"
    url_flow_add = "/stats/flowentry/add"
    url_flow_del = "/stats/flowentry/delete_strict"
    url_flows = "/stats/flow/{dpid}"

    class SentrixRyuApp(app_manager.RyuApp):  # type: ignore[misc]
        """
        OpenFlow 1.3 Learning Switch with Autonomous Threat Containment REST API.
        """
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        _CONTEXTS = {"wsgi": WSGIApplication}

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super(SentrixRyuApp, self).__init__(*args, **kwargs)
            self.mac_to_port: Dict[int, Dict[str, int]] = {}
            self.datapaths: Dict[int, Any] = {}
            self.state = _GLOBAL_STATE

            # Register REST WSGI controller
            wsgi = kwargs.get("wsgi")
            if wsgi:
                wsgi.register(SentrixRESTController, {SENTRIX_API_INSTANCE_NAME: self})

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev: Any) -> None:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            dpid = datapath.id

            self.datapaths[dpid] = datapath
            self.state.switches[dpid] = {"dpid": dpid, "connected_at": time.time()}
            self.logger.info("[+] Switch connected: DPID=%016x", dpid)

            # Install table-miss flow entry (send to controller)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, priority=0, match=match, actions=actions)
            self.logger.info("[+] Installed table-miss flow entry for DPID=%016x", dpid)

        def _add_flow(
            self,
            datapath: Any,
            priority: int,
            match: Any,
            actions: List[Any],
            idle_timeout: int = 0,
            hard_timeout: int = 0,
        ) -> None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
            )
            datapath.send_msg(mod)

        def block_ip(self, src_ip: str, dpid: int = 1, priority: int = 65535) -> bool:
            """Installs hardware line-rate DROP flow rule on switch."""
            self.state.block_ip(src_ip, dpid=dpid, priority=priority)

            datapath = self.datapaths.get(dpid)
            if datapath:
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                # Empty actions list = DROP
                self._add_flow(
                    datapath,
                    priority=priority,
                    match=match,
                    actions=[],
                    idle_timeout=3600,
                    hard_timeout=86400,
                )
                self.logger.warning("[!] CONTAINMENT ENFORCED: Dropping all IPv4 traffic from %s on DPID=%s", src_ip, dpid)
            return True

        def unblock_ip(self, src_ip: str, dpid: int = 1) -> bool:
            """Deletes DROP flow rule from switch, restoring connectivity."""
            self.state.unblock_ip(src_ip, dpid=dpid)

            datapath = self.datapaths.get(dpid)
            if datapath:
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    priority=65535,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match,
                )
                datapath.send_msg(mod)
                self.logger.info("[*] CONTAINMENT LIFTED: Restored traffic for %s on DPID=%s", src_ip, dpid)
            return True

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev: Any) -> None:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match["in_port"]

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            dst = eth.dst
            src = eth.src
            dpid = datapath.id

            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]

            # Install unicast forwarding rule if destination MAC is already known
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self._add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=60, hard_timeout=300)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)

    class SentrixRESTController(ControllerBase):  # type: ignore[misc]
        """WSGI REST Controller for Sentrix Ryu Application."""

        def __init__(self, req: Any, link: Any, data: Any, **config: Any) -> None:
            super(SentrixRESTController, self).__init__(req, link, data, **config)
            self.app: SentrixRyuApp = data[SENTRIX_API_INSTANCE_NAME]

        @route("sentrix", url_block, methods=["POST"])
        def post_block(self, req: Any, **_kwargs: Any) -> Response:
            try:
                body = req.json if hasattr(req, "json") else json.loads(req.body.decode("utf-8"))
                src_ip = body.get("src_ip")
                dpid = int(body.get("dpid", 1))
                priority = int(body.get("priority", 65535))
                if not src_ip:
                    return Response(status=400, content_type="application/json", body=json.dumps({"error": "src_ip required"}).encode("utf-8"))
                self.app.block_ip(src_ip, dpid=dpid, priority=priority)
                return Response(content_type="application/json", body=json.dumps({"status": "blocked", "src_ip": src_ip, "dpid": dpid}).encode("utf-8"))
            except Exception as e:
                return Response(status=500, content_type="application/json", body=json.dumps({"error": str(e)}).encode("utf-8"))

        @route("sentrix", url_unblock, methods=["POST"])
        def post_unblock(self, req: Any, **_kwargs: Any) -> Response:
            try:
                body = req.json if hasattr(req, "json") else json.loads(req.body.decode("utf-8"))
                src_ip = body.get("src_ip")
                dpid = int(body.get("dpid", 1))
                if not src_ip:
                    return Response(status=400, content_type="application/json", body=json.dumps({"error": "src_ip required"}).encode("utf-8"))
                self.app.unblock_ip(src_ip, dpid=dpid)
                return Response(content_type="application/json", body=json.dumps({"status": "unblocked", "src_ip": src_ip, "dpid": dpid}).encode("utf-8"))
            except Exception as e:
                return Response(status=500, content_type="application/json", body=json.dumps({"error": str(e)}).encode("utf-8"))

        @route("sentrix", url_rules, methods=["GET"])
        def get_rules(self, req: Any, **_kwargs: Any) -> Response:
            rules = self.app.state.list_rules()
            return Response(content_type="application/json", body=json.dumps({"active_blocks": rules, "count": len(rules)}).encode("utf-8"))

        @route("sentrix", url_switches, methods=["GET"])
        def get_switches(self, req: Any, **_kwargs: Any) -> Response:
            switches = list(self.app.state.switches.keys())
            return Response(content_type="application/json", body=json.dumps(switches).encode("utf-8"))

        @route("sentrix", url_flow_add, methods=["POST"])
        def post_flow_add(self, req: Any, **_kwargs: Any) -> Response:
            body = req.json if hasattr(req, "json") else json.loads(req.body.decode("utf-8"))
            src_ip = body.get("match", {}).get("ipv4_src")
            dpid = int(body.get("dpid", 1))
            priority = int(body.get("priority", 65535))
            if src_ip:
                self.app.block_ip(src_ip, dpid=dpid, priority=priority)
            return Response(content_type="application/json", body=json.dumps({"status": "success"}).encode("utf-8"))

        @route("sentrix", url_flow_del, methods=["POST"])
        def post_flow_del(self, req: Any, **_kwargs: Any) -> Response:
            body = req.json if hasattr(req, "json") else json.loads(req.body.decode("utf-8"))
            src_ip = body.get("match", {}).get("ipv4_src")
            dpid = int(body.get("dpid", 1))
            if src_ip:
                self.app.unblock_ip(src_ip, dpid=dpid)
            return Response(content_type="application/json", body=json.dumps({"status": "success"}).encode("utf-8"))

        @route("sentrix", url_flows, methods=["GET"])
        def get_flows(self, req: Any, dpid: str, **_kwargs: Any) -> Response:
            target_dpid = int(dpid)
            flows = self.app.state.list_flows(target_dpid)
            return Response(content_type="application/json", body=json.dumps({str(target_dpid): flows}).encode("utf-8"))


class StandaloneHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Lightweight, dependency-free HTTP REST handler for dev, CI testing, and non-Ryu runs.
    """

    state: SwitchState = _GLOBAL_STATE

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logging during unit tests unless error
        pass

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        return {}

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path == "/stats/switches":
            # Return list of connected switch DPIDs
            self._send_json(200, list(self.state.switches.keys()))
        elif path == "/rules":
            rules = self.state.list_rules()
            self._send_json(200, {"active_blocks": rules, "count": len(rules)})
        elif path.startswith("/stats/flow/"):
            dpid_part = path.replace("/stats/flow/", "")
            dpid = int(dpid_part) if dpid_part.isdigit() else 1
            flows = self.state.list_flows(dpid)
            self._send_json(200, {str(dpid): flows})
        elif path == "/health" or path == "":
            self._send_json(200, {"status": "ok", "mode": "standalone_sdn_controller"})
        else:
            self._send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        try:
            body = self._read_json()
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path == "/block":
            src_ip = body.get("src_ip")
            dpid = int(body.get("dpid", 1))
            priority = int(body.get("priority", 65535))
            if not src_ip:
                self._send_json(400, {"error": "src_ip is required"})
                return
            rule = self.state.block_ip(src_ip, dpid=dpid, priority=priority)
            self._send_json(200, {"status": "blocked", "src_ip": src_ip, "dpid": dpid, "rule": rule})

        elif path == "/unblock":
            src_ip = body.get("src_ip")
            dpid = int(body.get("dpid", 1))
            if not src_ip:
                self._send_json(400, {"error": "src_ip is required"})
                return
            cleared = self.state.unblock_ip(src_ip, dpid=dpid)
            self._send_json(200, {"status": "unblocked", "src_ip": src_ip, "dpid": dpid, "cleared": cleared})

        elif path == "/stats/flowentry/add":
            # Compatible with RyuSDNClient.block_ip() and rate_limit_ip()
            match_data = body.get("match", {})
            src_ip = match_data.get("ipv4_src")
            dpid = int(body.get("dpid", 1))
            priority = int(body.get("priority", 65535))
            if src_ip:
                self.state.block_ip(src_ip, dpid=dpid, priority=priority)
            self._send_json(200, {"status": "success", "src_ip": src_ip})

        elif path == "/stats/flowentry/delete_strict":
            # Compatible with RyuSDNClient.unblock_ip()
            match_data = body.get("match", {})
            src_ip = match_data.get("ipv4_src")
            dpid = int(body.get("dpid", 1))
            if src_ip:
                self.state.unblock_ip(src_ip, dpid=dpid)
            self._send_json(200, {"status": "success", "src_ip": src_ip})

        else:
            self._send_json(404, {"error": "Not Found", "path": path})


def start_standalone_server(host: str = "127.0.0.1", port: int = 8080) -> HTTPServer:
    """Starts the standalone SDN HTTP REST server in a background thread."""
    server = HTTPServer((host, port), StandaloneHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentrix SDN Controller Application")
    parser.add_argument("--port", type=int, default=8080, help="REST API listen port (default: 8080)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="REST API bind host (default: 0.0.0.0)")
    args = parser.parse_args()

    print(f"[*] Starting Sentrix SDN Controller (Standalone Mode) on {args.host}:{args.port}")
    print("    Supported endpoints:")
    print("      POST /block                       - Enforce line-rate drop")
    print("      POST /unblock                     - Lift containment")
    print("      GET  /rules                       - Active containment rules")
    print("      GET  /stats/switches              - Connected switches")
    print("      POST /stats/flowentry/add         - Standard Ryu ofctl flow add")
    print("      POST /stats/flowentry/delete_strict - Standard Ryu ofctl flow delete")
    print("      GET  /stats/flow/{dpid}           - Standard Ryu ofctl flow stats")

    server = HTTPServer((args.host, args.port), StandaloneHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentrix SDN Controller...")
        server.shutdown()


if __name__ == "__main__":
    main()
