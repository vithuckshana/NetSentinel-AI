"""
NetSentinel AI - Global Application State & WebSocket Broadcast Manager
Coordinates the packet sniffer, flow meter, hybrid ML engine, and real-time WebSocket feeds.
"""

import asyncio
import json
import random
import time
from typing import List, Dict, Any, Optional
from collections import deque
from ..engine.flow_meter import Flow
from ..engine.sniffer import NetworkSniffer
from ..engine.hybrid_engine import HybridEngine
from ..ml.predictor import ThreatPredictor

class AppState:
    def __init__(self):
        self.predictor = ThreatPredictor()
        self.hybrid_engine = HybridEngine(self.predictor)
        
        # Sniffer
        self.sniffer: Optional[NetworkSniffer] = None
        self.is_sniffing = False
        self.simulated_traffic_active = True
        
        # In-memory fast ring buffers
        self.recent_flows: deque = deque(maxlen=200)
        self.recent_alerts: deque = deque(maxlen=100)
        self.recent_packets: deque = deque(maxlen=50)
        
        # Global Counters
        self.total_packets_monitored = 0
        self.total_flows_monitored = 0
        self.total_threats_detected = 0
        self.threat_counts_by_type = {
            "PortScan": 0,
            "DoS": 0,
            "Brute Force": 0
        }
        
        # Active WebSockets
        self.active_websockets: List[Any] = []
        self._sim_task: Optional[asyncio.Task] = None
        self.main_loop: Optional[asyncio.AbstractEventLoop] = None

    async def broadcast_ws(self, message: Dict[str, Any]):
        """Send JSON message to all connected dashboard WebSockets."""
        if not self.active_websockets:
            return
        payload = json.dumps(message)
        dead = []
        for ws in self.active_websockets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for d in dead:
            if d in self.active_websockets:
                self.active_websockets.remove(d)

    def handle_packet_seen(self, pkt_meta: Dict[str, Any]):
        """Callback from Scapy packet capture."""
        self.total_packets_monitored += 1
        self.recent_packets.append(pkt_meta)

    def handle_completed_flow(self, flow: Flow):
        """Callback when a flow times out and is ready for ML classification."""
        self.total_flows_monitored += 1
        
        # 1. Run Hybrid Detection (ML + Rules)
        alert = self.hybrid_engine.process_flow(flow)
        
        # 2. Extract classification metadata
        ml_res = self.predictor.predict_flow(flow)
        flow_entry = {
            "id": f"FLW-{int(time.time()*1000) % 1_000_000:06d}",
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else "ICMP"),
            "packets": len(flow.all_timestamps),
            "bytes": sum(flow.fwd_pkt_lens) + sum(flow.bwd_pkt_lens),
            "duration_ms": round((flow.last_seen - flow.start_time) * 1000.0, 2),
            "label": ml_res["predicted_class"],
            "confidence": ml_res["confidence"],
            "severity": ml_res["severity"]
        }
        self.recent_flows.append(flow_entry)
        
        # 3. Handle Alert if detected
        if alert:
            self.total_threats_detected += 1
            if alert["attack_type"] in self.threat_counts_by_type:
                self.threat_counts_by_type[alert["attack_type"]] += 1
            self.recent_alerts.append(alert)
            
            # Fire alert event to WebSockets
            if self.main_loop and self.main_loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_ws({"type": "ALERT", "data": alert}), 
                    self.main_loop
                )
                
        # Emit flow event to WebSockets
        if self.main_loop and self.main_loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.broadcast_ws({"type": "FLOW", "data": flow_entry}), 
                self.main_loop
            )

    async def run_traffic_simulator(self):
        """Generates realistic background live network traffic for demonstrations."""
        benign_hosts = [
            ("192.168.1.102", "142.250.190.46", 443, "TCP"),
            ("192.168.1.105", "1.1.1.1", 53, "UDP"),
            ("192.168.1.110", "192.168.1.1", 80, "TCP"),
            ("192.168.1.115", "172.217.16.206", 443, "TCP"),
            ("192.168.1.108", "192.168.1.254", 123, "UDP"),
        ]
        
        while self.simulated_traffic_active:
            await asyncio.sleep(random.uniform(0.6, 1.8))
            
            # Pick a benign communication
            src_ip, dst_ip, dst_port, proto_name = random.choice(benign_hosts)
            src_port = random.randint(32768, 61000)
            proto_num = 6 if proto_name == "TCP" else 17
            
            now = time.time()
            flow = Flow(src_ip, dst_ip, src_port, dst_port, proto_num, now - random.uniform(0.1, 2.0))
            
            pkts = random.randint(4, 18)
            for _ in range(pkts):
                flow.add_packet(
                    length=random.randint(64, 1420),
                    timestamp=now,
                    is_forward=random.choice([True, False]),
                    flags={"SYN": False, "ACK": True, "PSH": True}
                )
            
            self.total_packets_monitored += pkts
            self.handle_completed_flow(flow)

    def trigger_attack_simulation(self, attack_type: str) -> Dict[str, Any]:
        """Injects a controlled attack flow on demand for viva and defense demonstrations."""
        now = time.time()
        
        if attack_type == "PortScan":
            src_ip = f"192.168.1.{random.randint(180, 240)}"
            dst_ip = "192.168.1.10" # Target server
            # Simulate a series of scans
            created_alerts = []
            for target_port in random.sample(range(20, 1024), 12):
                flow = Flow(src_ip, dst_ip, random.randint(40000, 60000), target_port, 6, now)
                flow.add_packet(length=44, timestamp=now, is_forward=True, flags={"SYN": True, "ACK": False})
                self.total_packets_monitored += 1
                self.handle_completed_flow(flow)
            return {"status": "SUCCESS", "message": f"Simulated {attack_type} against {dst_ip}."}

        elif attack_type == "DoS":
            src_ip = f"10.0.0.{random.randint(50, 99)}"
            dst_ip = "192.168.1.50"
            dst_port = 80
            flow = Flow(src_ip, dst_ip, 44882, dst_port, 6, now - 0.5)
            # Flood with 250 forward packets
            for _ in range(250):
                flow.add_packet(length=54, timestamp=now, is_forward=True, flags={"SYN": True, "ACK": False})
            self.total_packets_monitored += 250
            self.handle_completed_flow(flow)
            return {"status": "SUCCESS", "message": f"Simulated {attack_type} flood against {dst_ip}:{dst_port}."}

        elif attack_type == "Brute Force":
            src_ip = "192.168.1.199"
            dst_ip = "192.168.1.20"
            dst_port = 22 # SSH
            for _ in range(6):
                flow = Flow(src_ip, dst_ip, random.randint(45000, 65000), dst_port, 6, now)
                for _ in range(12):
                    flow.add_packet(length=120, timestamp=now, is_forward=True, flags={"SYN": True, "PSH": True, "ACK": True})
                self.total_packets_monitored += 12
                self.handle_completed_flow(flow)
            return {"status": "SUCCESS", "message": f"Simulated {attack_type} against SSH on {dst_ip}:22."}

        return {"status": "ERROR", "message": f"Unknown attack type: {attack_type}"}

# Global singleton
state = AppState()
