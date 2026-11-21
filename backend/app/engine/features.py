"""
NetSentinel AI - Network Flow Feature Schema
Aligned with the Canadian Institute for Cybersecurity (CICIDS2017) feature standards.
Ensures 100% compatibility between live packet capture and machine learning models.
"""

FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size"
]

# Attack Class Labels
ATTACK_CLASSES = [
    "BENIGN",
    "PortScan",
    "DoS",
    "Brute Force"
]

LABEL_TO_ID = {label: idx for idx, label in enumerate(ATTACK_CLASSES)}
ID_TO_LABEL = {idx: label for idx, label in enumerate(ATTACK_CLASSES)}

# Severity mapping for triage
ATTACK_SEVERITY = {
    "BENIGN": "Low",
    "PortScan": "Medium",
    "Brute Force": "High",
    "DoS": "Critical"
}
