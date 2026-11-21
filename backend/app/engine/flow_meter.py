"""
NetSentinel AI - Bidirectional Network Flow Meter
Aggregates network packets into bidirectional 5-tuple flows and extracts
CICIDS2017-compatible statistical features in real-time.
"""

import time
import math
from typing import Dict, List, Optional, Tuple, Any
from .features import FEATURE_NAMES

class Flow:
    """Represents a single bidirectional network flow."""
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = start_time
        self.last_seen = start_time
        
        # Packet lengths
        self.fwd_pkt_lens: List[int] = []
        self.bwd_pkt_lens: List[int] = []
        
        # Packet timestamps for Inter-Arrival Time (IAT)
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []
        
        # Header lengths (bytes)
        self.fwd_header_len: int = 0
        self.bwd_header_len: int = 0
        
        # TCP Flags counts
        self.fin_cnt: int = 0
        self.syn_cnt: int = 0
        self.rst_cnt: int = 0
        self.psh_cnt: int = 0
        self.ack_cnt: int = 0
        self.urg_cnt: int = 0
        self.fwd_psh_cnt: int = 0
        self.bwd_psh_cnt: int = 0

    def add_packet(self, length: int, timestamp: float, is_forward: bool, header_len: int = 20, flags: Optional[Dict[str, bool]] = None):
        """Add packet details to the flow."""
        self.last_seen = max(self.last_seen, timestamp)
        self.all_timestamps.append(timestamp)
        
        if is_forward:
            self.fwd_pkt_lens.append(length)
            self.fwd_timestamps.append(timestamp)
            self.fwd_header_len += header_len
        else:
            self.bwd_pkt_lens.append(length)
            self.bwd_timestamps.append(timestamp)
            self.bwd_header_len += header_len
            
        if flags:
            if flags.get("FIN"): self.fin_cnt += 1
            if flags.get("SYN"): self.syn_cnt += 1
            if flags.get("RST"): self.rst_cnt += 1
            if flags.get("PSH"): 
                self.psh_cnt += 1
                if is_forward: self.fwd_psh_cnt += 1
                else: self.bwd_psh_cnt += 1
            if flags.get("ACK"): self.ack_cnt += 1
            if flags.get("URG"): self.urg_cnt += 1

    @staticmethod
    def _stats(arr: List[float]) -> Tuple[float, float, float, float]:
        """Compute (min, max, mean, std) safely."""
        if not arr:
            return 0.0, 0.0, 0.0, 0.0
        n = len(arr)
        min_v = float(min(arr))
        max_v = float(max(arr))
        mean_v = float(sum(arr)) / n
        if n > 1:
            variance = sum((x - mean_v) ** 2 for x in arr) / (n - 1)
            std_v = math.sqrt(max(0.0, variance))
        else:
            std_v = 0.0
        return min_v, max_v, mean_v, std_v

    @staticmethod
    def _iat(timestamps: List[float]) -> Tuple[float, float, float, float]:
        """Compute inter-arrival time statistics in microseconds."""
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0
        sorted_ts = sorted(timestamps)
        # Convert seconds to microseconds (* 1e6) to match CICIDS2017
        diffs = [(sorted_ts[i] - sorted_ts[i-1]) * 1e6 for i in range(1, len(sorted_ts))]
        return Flow._stats(diffs)

    def extract_features(self) -> Dict[str, float]:
        """Calculate and return the 49 CICIDS2017 compatible features."""
        # Duration in microseconds
        duration_sec = max(0.0, self.last_seen - self.start_time)
        duration_us = duration_sec * 1e6
        
        tot_fwd_pkts = len(self.fwd_pkt_lens)
        tot_bwd_pkts = len(self.bwd_pkt_lens)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        
        tot_fwd_len = sum(self.fwd_pkt_lens)
        tot_bwd_len = sum(self.bwd_pkt_lens)
        tot_bytes = tot_fwd_len + tot_bwd_len
        all_pkt_lens = self.fwd_pkt_lens + self.bwd_pkt_lens
        
        # Packet length statistics
        fwd_min, fwd_max, fwd_mean, fwd_std = self._stats(self.fwd_pkt_lens)
        bwd_min, bwd_max, bwd_mean, bwd_std = self._stats(self.bwd_pkt_lens)
        all_min, all_max, all_mean, all_std = self._stats(all_pkt_lens)
        pkt_len_var = all_std ** 2
        
        # Rates
        sec_safe = duration_sec if duration_sec > 1e-6 else 1e-6
        flow_bytes_s = tot_bytes / sec_safe
        flow_pkts_s = tot_pkts / sec_safe
        fwd_pkts_s = tot_fwd_pkts / sec_safe
        bwd_pkts_s = tot_bwd_pkts / sec_safe
        
        # IAT stats
        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std = self._iat(self.all_timestamps)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = self._iat(self.fwd_timestamps)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = self._iat(self.bwd_timestamps)
        
        down_up_ratio = (tot_bwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0.0
        avg_pkt_size = (tot_bytes / tot_pkts) if tot_pkts > 0 else 0.0
        
        features: Dict[str, float] = {
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(tot_fwd_pkts),
            "Total Backward Packets": float(tot_bwd_pkts),
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Total Length of Bwd Packets": float(tot_bwd_len),
            "Fwd Packet Length Max": float(fwd_max),
            "Fwd Packet Length Min": float(fwd_min),
            "Fwd Packet Length Mean": float(fwd_mean),
            "Fwd Packet Length Std": float(fwd_std),
            "Bwd Packet Length Max": float(bwd_max),
            "Bwd Packet Length Min": float(bwd_min),
            "Bwd Packet Length Mean": float(bwd_mean),
            "Bwd Packet Length Std": float(bwd_std),
            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_pkts_s),
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Max": float(fwd_iat_max),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": float(self.fwd_psh_cnt),
            "Bwd PSH Flags": float(self.bwd_psh_cnt),
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Fwd Packets/s": float(fwd_pkts_s),
            "Bwd Packets/s": float(bwd_pkts_s),
            "Min Packet Length": float(all_min),
            "Max Packet Length": float(all_max),
            "Packet Length Mean": float(all_mean),
            "Packet Length Std": float(all_std),
            "Packet Length Variance": float(pkt_len_var),
            "FIN Flag Count": float(self.fin_cnt),
            "SYN Flag Count": float(self.syn_cnt),
            "RST Flag Count": float(self.rst_cnt),
            "PSH Flag Count": float(self.psh_cnt),
            "ACK Flag Count": float(self.ack_cnt),
            "URG Flag Count": float(self.urg_cnt),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_pkt_size),
            "Avg Fwd Segment Size": float(fwd_mean),
            "Avg Bwd Segment Size": float(bwd_mean)
        }
        return features

    def to_feature_vector(self) -> List[float]:
        """Return list of feature values in the exact canonical order."""
        features = self.extract_features()
        return [features[f] for f in FEATURE_NAMES]


class FlowManager:
    """Tracks active network flows and flushes them on timeout."""
    def __init__(self, idle_timeout: float = 5.0, active_timeout: float = 60.0):
        self.flows: Dict[str, Flow] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

    def _get_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> Tuple[str, bool]:
        """Canonical key lookup. Returns (flow_id, is_forward)."""
        forward_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}#{protocol}"
        backward_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}#{protocol}"
        
        if forward_key in self.flows:
            return forward_key, True
        if backward_key in self.flows:
            return backward_key, False
        # New flow
        return forward_key, True

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        length: int,
        timestamp: Optional[float] = None,
        header_len: int = 20,
        flags: Optional[Dict[str, bool]] = None
    ) -> Flow:
        """Process incoming packet, update flow or create new flow."""
        if timestamp is None:
            timestamp = time.time()
            
        key, is_forward = self._get_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        if key not in self.flows:
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
            self.flows[key] = flow
        else:
            flow = self.flows[key]
            
        flow.add_packet(length, timestamp, is_forward, header_len, flags)
        return flow

    def flush_expired_flows(self, current_time: Optional[float] = None) -> List[Flow]:
        """Return and remove flows that exceeded idle or active timeouts."""
        if current_time is None:
            current_time = time.time()
            
        expired: List[Flow] = []
        keys_to_remove: List[str] = []
        
        for key, flow in self.flows.items():
            idle_time = current_time - flow.last_seen
            active_time = current_time - flow.start_time
            
            if idle_time > self.idle_timeout or active_time > self.active_timeout:
                expired.append(flow)
                keys_to_remove.append(key)
                
        for key in keys_to_remove:
            del self.flows[key]
            
        return expired
