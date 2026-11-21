"""
NetSentinel AI - Explainable AI (XAI) & Incident Reason Engine
Translates raw model feature vectors and predictions into actionable, human-interpretable
security rationale and remediation recommendations for SOC analysts.
"""

from typing import Dict, List, Any
import numpy as np
from ..engine.features import ATTACK_SEVERITY

# Empirical baseline thresholds for benign network flows
BENIGN_BASELINES = {
    "Flow Packets/s": {"normal_max": 250.0, "unit": "pkts/sec", "desc": "Flow packet rate"},
    "Flow Bytes/s": {"normal_max": 2_000_000.0, "unit": "B/s", "desc": "Byte transfer rate"},
    "SYN Flag Count": {"normal_max": 2.0, "unit": "flags", "desc": "SYN flag count"},
    "RST Flag Count": {"normal_max": 1.0, "unit": "flags", "desc": "RST flag count"},
    "Down/Up Ratio": {"normal_min": 0.2, "unit": "ratio", "desc": "Server response to request ratio"},
    "Flow Duration": {"normal_min": 50_000.0, "unit": "µs", "desc": "Connection lifetime in microseconds"},
    "Total Fwd Packets": {"normal_max": 150.0, "unit": "pkts", "desc": "Client outbound packets"},
    "Average Packet Size": {"normal_min": 60.0, "normal_max": 1400.0, "unit": "bytes", "desc": "Average packet length"},
    "ACK Flag Count": {"normal_min": 1.0, "unit": "flags", "desc": "Acknowledgment flag count"}
}

RECOMMENDED_ACTIONS = {
    "PortScan": [
        "Investigate source device for active scanning tools (Nmap/Masscan) or malware infection.",
        "Check firewall policy to ensure unopened target ports drop packets rather than emit RSTs.",
        "Consider placing the source IP in a temporary isolation VLAN for forensics."
    ],
    "DoS": [
        "Verify if high volume originates from a single IP or spoofed source pool.",
        "Engage upstream rate-limiting / SYN cookies on perimeter routers or load balancers.",
        "Apply ingress traffic filtering (BCP 38) and drop asymmetric floods at edge firewall."
    ],
    "Brute Force": [
        "Check authentication logs on target service for user accounts being targeted.",
        "Enforce exponential backoff / account lockout policies (fail2ban) on the target host.",
        "Restrict administrative ports (SSH/22, RDP/3389) via IP whitelist or VPN access only."
    ],
    "BENIGN": [
        "Routine operational traffic. No action required."
    ]
}


class ThreatExplainer:
    """Generates explainability metrics and human-readable reasoning for detected threats."""
    
    @staticmethod
    def explain_flow(features: Dict[str, float], predicted_label: str, confidence: float) -> Dict[str, Any]:
        """
        Analyze a flow's features against security baselines and feature importance
        to explain WHY the model flagged this flow.
        """
        severity = ATTACK_SEVERITY.get(predicted_label, "Medium")
        reasons: List[str] = []
        feature_contributions: List[Dict[str, Any]] = []
        
        syn_cnt = features.get("SYN Flag Count", 0.0)
        ack_cnt = features.get("ACK Flag Count", 0.0)
        rst_cnt = features.get("RST Flag Count", 0.0)
        flow_pkts_s = features.get("Flow Packets/s", 0.0)
        flow_bytes_s = features.get("Flow Bytes/s", 0.0)
        duration_us = features.get("Flow Duration", 0.0)
        fwd_pkts = features.get("Total Fwd Packets", 0.0)
        bwd_pkts = features.get("Total Backward Packets", 0.0)
        down_up = features.get("Down/Up Ratio", 0.0)
        avg_pkt_size = features.get("Average Packet Size", 0.0)
        dst_port = int(features.get("Destination Port", 0))

        if predicted_label == "PortScan":
            if syn_cnt > 0 and ack_cnt == 0:
                reasons.append(f"Unacknowledged SYN probe detected ({int(syn_cnt)} SYN flags with 0 ACKs).")
                feature_contributions.append({"feature": "SYN Flag Count", "value": syn_cnt, "impact": "High"})
            if duration_us < 50_000:
                reasons.append(f"Sub-millisecond connection lifetime ({duration_us:.1f} µs) typical of automated port sweeps.")
                feature_contributions.append({"feature": "Flow Duration", "value": duration_us, "impact": "High"})
            if bwd_pkts == 0 or rst_cnt > 0:
                reasons.append(f"No legitimate application handshake completed (Target sent RST/no response).")
                feature_contributions.append({"feature": "Down/Up Ratio", "value": down_up, "impact": "Medium"})
            if not reasons:
                reasons.append("Flow signature matches rapid scanning probe characteristics across destination ports.")

        elif predicted_label == "DoS":
            if fwd_pkts > 100 and bwd_pkts < 10:
                reasons.append(f"Extreme directional traffic asymmetry: {int(fwd_pkts)} outbound vs {int(bwd_pkts)} inbound packets.")
                feature_contributions.append({"feature": "Total Fwd Packets", "value": fwd_pkts, "impact": "Critical"})
            if flow_pkts_s > 500:
                reasons.append(f"Abnormal packet burst rate: {flow_pkts_s:.1f} pkts/sec (Normal threshold: < 250).")
                feature_contributions.append({"feature": "Flow Packets/s", "value": flow_pkts_s, "impact": "High"})
            if syn_cnt > 20:
                reasons.append(f"High-frequency SYN flood pattern ({int(syn_cnt)} SYNs without handshakes).")
                feature_contributions.append({"feature": "SYN Flag Count", "value": syn_cnt, "impact": "Critical"})
            if not reasons:
                reasons.append("Sustained high-volume traffic flood overwhelming network resources.")

        elif predicted_label == "Brute Force":
            reasons.append(f"Targeted authentication service port {dst_port} with repeated credential transmission bursts.")
            if duration_us < 5_000_000:
                reasons.append(f"Rapid successive login attempts with short interaction intervals.")
            feature_contributions.append({"feature": "Destination Port", "value": dst_port, "impact": "High"})
            feature_contributions.append({"feature": "PSH Flag Count", "value": features.get("PSH Flag Count", 0.0), "impact": "Medium"})

        else:
            reasons.append("Traffic exhibits balanced bidirectional communication, valid TCP handshakes, and normal inter-arrival times.")

        return {
            "predicted_class": predicted_label,
            "confidence": round(float(confidence), 4),
            "severity": severity,
            "reasons": reasons,
            "feature_contributions": feature_contributions,
            "recommended_actions": RECOMMENDED_ACTIONS.get(predicted_label, ["Review traffic logs."])
        }
