"""
NetSentinel AI - Hybrid Threat Detection Engine
Combines Rule-Based Heuristic Signatures with Machine Learning Inference
for comprehensive multi-layered defense and low false-positive rates.
"""

import time
from typing import Dict, List, Any, Optional
from collections import defaultdict
from .flow_meter import Flow
from ..ml.predictor import ThreatPredictor


class HybridEngine:
    """
    Correlates signature/heuristic rules with AI/ML classifications
    to produce corroborated security alerts.
    """
    def __init__(self, predictor: ThreatPredictor):
        self.predictor = predictor
        
        # Sliding window state trackers for heuristics
        # Tracks {src_ip: [timestamp, dst_port]}
        self.port_scan_tracker = defaultdict(list)
        # Tracks {src_ip: [timestamp, syn_count]}
        self.syn_flood_tracker = defaultdict(list)
        # Tracks {(src_ip, dst_ip, dst_port): [timestamps]}
        self.auth_attempt_tracker = defaultdict(list)
        
        # Alert throttling / deduplication {alert_fingerprint: last_alert_time}
        self.alert_cache: Dict[str, float] = {}
        self.throttle_seconds = 4.0

    def evaluate_heuristics(self, flow: Flow, now: float) -> List[Dict[str, Any]]:
        """Evaluate deterministic security rules over recent sliding time windows."""
        triggered_rules = []
        
        # 1. Port Sweep Rule (Threshold: > 10 distinct ports contacted in 10s)
        self.port_scan_tracker[flow.src_ip].append((now, flow.dst_port))
        # Prune older than 10s
        self.port_scan_tracker[flow.src_ip] = [
            (t, p) for t, p in self.port_scan_tracker[flow.src_ip] if now - t <= 10.0
        ]
        unique_ports = {p for _, p in self.port_scan_tracker[flow.src_ip]}
        if len(unique_ports) >= 8:
            triggered_rules.append({
                "rule_id": "RULE-PORT-001",
                "name": "Horizontal/Vertical Port Sweep Pattern",
                "attack_type": "PortScan",
                "severity": "Medium",
                "details": f"Source {flow.src_ip} queried {len(unique_ports)} distinct ports within 10 seconds."
            })
            
        # 2. SYN Flood Heuristic (Threshold: > 50 SYN packets without ACK within 5s)
        if flow.syn_cnt > 0 and flow.ack_cnt == 0:
            self.syn_flood_tracker[flow.src_ip].append((now, flow.syn_cnt))
            # Prune older than 5s
            self.syn_flood_tracker[flow.src_ip] = [
                (t, s) for t, s in self.syn_flood_tracker[flow.src_ip] if now - t <= 5.0
            ]
            total_recent_syn = sum(s for _, s in self.syn_flood_tracker[flow.src_ip])
            if total_recent_syn >= 25 or flow.syn_cnt >= 20:
                triggered_rules.append({
                    "rule_id": "RULE-DOS-002",
                    "name": "High-Volume Unanswered SYN Flood",
                    "attack_type": "DoS",
                    "severity": "Critical",
                    "details": f"High frequency SYN flood detected: {total_recent_syn} unacknowledged connection requests."
                })

        # 3. Brute Force Heuristic (Threshold: repeated connections to auth ports: 21, 22, 3389)
        if flow.dst_port in [21, 22, 3389, 23]:
            auth_key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            self.auth_attempt_tracker[auth_key].append(now)
            self.auth_attempt_tracker[auth_key] = [
                t for t in self.auth_attempt_tracker[auth_key] if now - t <= 15.0
            ]
            if len(self.auth_attempt_tracker[auth_key]) >= 5:
                triggered_rules.append({
                    "rule_id": "RULE-AUTH-003",
                    "name": "Repeated Authentication Burst",
                    "attack_type": "Brute Force",
                    "severity": "High",
                    "details": f"{len(self.auth_attempt_tracker[auth_key])} rapid connection attempts to authentication port {flow.dst_port}."
                })
                
        return triggered_rules

    def process_flow(self, flow: Flow, model_choice: str = "Random Forest") -> Optional[Dict[str, Any]]:
        """
        Correlate ML inference with Rule-based engine.
        Returns an Alert dictionary if malicious activity is corroborated or detected.
        """
        now = time.time()
        
        # 1. Run Machine Learning Inference & XAI
        ml_result = self.predictor.predict_flow(flow, model_choice=model_choice)
        ml_class = ml_result["predicted_class"]
        ml_confidence = ml_result["confidence"]
        
        # 2. Run Heuristic Rules
        heuristic_rules = self.evaluate_heuristics(flow, now)
        has_rule_match = len(heuristic_rules) > 0
        rule_attack_types = [r["attack_type"] for r in heuristic_rules]
        
        # 3. Hybrid Arbitration Logic
        is_threat = False
        final_attack_type = "BENIGN"
        final_severity = "Low"
        detection_mechanism = "None"
        corroborated = False
        
        if has_rule_match and ml_class != "BENIGN":
            # Maximum Confidence: Both ML and Rule Engine agree!
            is_threat = True
            final_attack_type = ml_class
            final_severity = heuristic_rules[0]["severity"]
            detection_mechanism = "Hybrid (AI/ML + Rule Corroborated)"
            corroborated = True
            ml_result["confidence"] = min(0.999, ml_confidence + 0.05)
        elif ml_class != "BENIGN" and ml_confidence >= 0.70:
            # AI-Driven Detection (Zero-Day or pattern not hardcoded in rules)
            is_threat = True
            final_attack_type = ml_class
            final_severity = ml_result["severity"]
            detection_mechanism = "AI/ML Detection Engine"
        elif has_rule_match:
            # Rule Engine Triggered (Heuristic override)
            is_threat = True
            final_attack_type = heuristic_rules[0]["attack_type"]
            final_severity = heuristic_rules[0]["severity"]
            detection_mechanism = "Signature Rule Engine"
            ml_result["confidence"] = 0.90
            
        if not is_threat:
            return None
            
        # 4. Alert Throttling & Deduplication
        fingerprint = f"{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}#{final_attack_type}"
        last_alert_time = self.alert_cache.get(fingerprint, 0.0)
        if (now - last_alert_time) < self.throttle_seconds:
            # Suppress duplicate alert flood
            return None
            
        self.alert_cache[fingerprint] = now
        
        # 5. Construct Comprehensive Security Alert
        alert = {
            "id": f"ALT-{int(now * 1000) % 1_000_000:06d}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else "ICMP"),
            "attack_type": final_attack_type,
            "severity": final_severity,
            "detection_mechanism": detection_mechanism,
            "corroborated": corroborated,
            "confidence": ml_result["confidence"],
            "status": "Unresolved",
            "triggered_rules": heuristic_rules,
            "flow_meta": ml_result["flow_meta"],
            "xai_explanation": ml_result["explanation"]
        }
        return alert
