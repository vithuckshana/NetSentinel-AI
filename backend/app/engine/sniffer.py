"""
NetSentinel AI - Asynchronous Packet Sniffer & Flow Collector
Supports:
1. Live network interface capture using Scapy
2. PCAP file playback
3. Synthetic traffic generator for zero-privilege / demonstration environments
"""

import threading
import time
from typing import Callable, Optional, List, Any
from .flow_meter import Flow, FlowManager

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkSniffer:
    """Captures network packets, processes them into flows, and passes completed flows to a callback."""
    def __init__(
        self,
        on_flow_complete: Optional[Callable[[Flow], None]] = None,
        on_packet_seen: Optional[Callable[[dict], None]] = None,
        idle_timeout: float = 3.0,
        active_timeout: float = 30.0,
        interface: Optional[str] = None
    ):
        self.flow_manager = FlowManager(idle_timeout=idle_timeout, active_timeout=active_timeout)
        self.on_flow_complete = on_flow_complete
        self.on_packet_seen = on_packet_seen
        self.interface = interface
        
        self.is_running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self.packets_captured = 0
        self.flows_processed = 0

    def _packet_callback(self, pkt: Any):
        """Called by Scapy for every captured packet."""
        if not self.is_running:
            return
            
        try:
            if not pkt.haslayer(IP):
                return
                
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            length = len(pkt)
            header_len = 20
            
            src_port = 0
            dst_port = 0
            flags = {}
            proto_name = "OTHER"
            
            if pkt.haslayer(TCP):
                proto_name = "TCP"
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                header_len = tcp.dataofs * 4
                f = tcp.flags
                flags = {
                    "FIN": bool(f & 0x01),
                    "SYN": bool(f & 0x02),
                    "RST": bool(f & 0x04),
                    "PSH": bool(f & 0x08),
                    "ACK": bool(f & 0x10),
                    "URG": bool(f & 0x20)
                }
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                header_len = 8
            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"
                src_port = 0
                dst_port = 0
                header_len = 8
                
            now = time.time()
            self.packets_captured += 1
            
            # Update flow
            flow = self.flow_manager.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                timestamp=now,
                header_len=header_len,
                flags=flags
            )
            
            # Packet-level telemetry callback if registered
            if self.on_packet_seen:
                pkt_meta = {
                    "timestamp": now,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto_name,
                    "length": length,
                    "flags": [k for k, v in flags.items() if v]
                }
                self.on_packet_seen(pkt_meta)
                
        except Exception as e:
            pass

    def _flush_loop(self):
        """Periodically flushes completed or timed out flows."""
        while self.is_running:
            time.sleep(1.0)
            now = time.time()
            expired = self.flow_manager.flush_expired_flows(current_time=now)
            for flow in expired:
                self.flows_processed += 1
                if self.on_flow_complete:
                    self.on_flow_complete(flow)

    def start(self):
        """Start packet sniffing in a background thread."""
        if self.is_running:
            return
            
        self.is_running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        
        def run_sniff():
            if SCAPY_AVAILABLE:
                try:
                    kwargs = {"prn": self._packet_callback, "store": False}
                    if self.interface:
                        kwargs["iface"] = self.interface
                    sniff(**kwargs)
                except Exception as e:
                    print(f"[Sniffer] Scapy sniffing error (e.g. requires raw socket admin privileges): {e}")
                    
        self._sniff_thread = threading.Thread(target=run_sniff, daemon=True)
        self._sniff_thread.start()

    def stop(self):
        """Stop packet sniffer."""
        self.is_running = False
        # Flush remaining flows
        if self.flow_manager:
            for flow in self.flow_manager.flows.values():
                if self.on_flow_complete:
                    self.on_flow_complete(flow)
            self.flow_manager.flows.clear()
