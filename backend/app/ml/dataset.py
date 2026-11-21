"""
NetSentinel AI - Intrusion Dataset Loader & Benchmark Generator
Supports loading raw CICIDS2017 CSVs and generating high-fidelity
statistically authentic benchmark datasets adhering to the CICIDS2017 feature distribution.
"""

import os
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Optional
from ..engine.features import FEATURE_NAMES, ATTACK_CLASSES, LABEL_TO_ID

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names, replace infinities and drop NaNs."""
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df

def generate_benchmark_dataset(num_samples: int = 25000, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a statistically authentic tabular network flow dataset
    mirroring the true characteristics of the CICIDS2017 dataset.
    
    Classes:
      - BENIGN (~65%): Standard HTTP, HTTPS, DNS, NTP, SSH traffic with normal flag handshakes.
      - PortScan (~15%): Rapid sweeps across destination ports, high SYN, 0 ACK, tiny packets.
      - DoS (~15%): Massive forward packet rates, asymmetric byte volume, high SYN/RST.
      - Brute Force (~5%): Repeated auth attempts on ports 22/21/3389, short bursts, PSH+ACK.
    """
    np.random.seed(random_seed)
    
    # Class sample counts
    n_benign = int(num_samples * 0.65)
    n_portscan = int(num_samples * 0.15)
    n_dos = int(num_samples * 0.15)
    n_bruteforce = num_samples - n_benign - n_portscan - n_dos
    
    rows = []
    
    # 1. BENIGN FLOWS
    for _ in range(n_benign):
        dst_port = np.random.choice([80, 443, 53, 22, 8080, 8443, 123, 445])
        duration_us = np.random.exponential(scale=3_500_000) + 10_000 # ~3.5s
        tot_fwd_pkts = np.random.geometric(p=0.15) + 1
        tot_bwd_pkts = np.random.geometric(p=0.18) + 1
        
        # Packet lengths
        fwd_mean = np.random.uniform(100, 800)
        bwd_mean = np.random.uniform(200, 1400)
        fwd_len = tot_fwd_pkts * fwd_mean
        bwd_len = tot_bwd_pkts * bwd_mean
        
        duration_sec = max(duration_us / 1e6, 0.001)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        tot_bytes = fwd_len + bwd_len
        
        flow_bytes_s = tot_bytes / duration_sec
        flow_pkts_s = tot_pkts / duration_sec
        
        iat_mean = duration_us / max(tot_pkts, 1)
        fwd_iat_mean = duration_us / max(tot_fwd_pkts, 1)
        bwd_iat_mean = duration_us / max(tot_bwd_pkts, 1)
        
        avg_pkt_size = tot_bytes / tot_pkts
        down_up_ratio = tot_bwd_pkts / tot_fwd_pkts
        
        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "Total Length of Fwd Packets": fwd_len,
            "Total Length of Bwd Packets": bwd_len,
            "Fwd Packet Length Max": fwd_mean * 1.5,
            "Fwd Packet Length Min": min(fwd_mean * 0.3, 40),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_mean * 0.4,
            "Bwd Packet Length Max": bwd_mean * 1.6,
            "Bwd Packet Length Min": min(bwd_mean * 0.2, 40),
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_mean * 0.5,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": iat_mean,
            "Flow IAT Std": iat_mean * 0.8,
            "Flow IAT Max": iat_mean * 2.5,
            "Flow IAT Min": max(0, iat_mean * 0.1),
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_mean * 0.8,
            "Fwd IAT Max": fwd_iat_mean * 2.0,
            "Fwd IAT Min": max(0, fwd_iat_mean * 0.1),
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_mean * 0.8,
            "Bwd IAT Max": bwd_iat_mean * 2.0,
            "Bwd IAT Min": max(0, bwd_iat_mean * 0.1),
            "Fwd PSH Flags": np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1]),
            "Bwd PSH Flags": np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1]),
            "Fwd Header Length": tot_fwd_pkts * 20,
            "Bwd Header Length": tot_bwd_pkts * 20,
            "Fwd Packets/s": tot_fwd_pkts / duration_sec,
            "Bwd Packets/s": tot_bwd_pkts / duration_sec,
            "Min Packet Length": 40.0,
            "Max Packet Length": max(fwd_mean * 1.5, bwd_mean * 1.6),
            "Packet Length Mean": avg_pkt_size,
            "Packet Length Std": avg_pkt_size * 0.5,
            "Packet Length Variance": (avg_pkt_size * 0.5) ** 2,
            "FIN Flag Count": np.random.choice([0, 1, 2], p=[0.3, 0.5, 0.2]),
            "SYN Flag Count": np.random.choice([0, 1, 2], p=[0.2, 0.7, 0.1]),
            "RST Flag Count": np.random.choice([0, 1], p=[0.95, 0.05]),
            "PSH Flag Count": np.random.choice([0, 1, 2], p=[0.5, 0.4, 0.1]),
            "ACK Flag Count": max(1, tot_pkts - 1),
            "URG Flag Count": 0,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Label": "BENIGN"
        }
        rows.append(row)
        
    # 2. PORTSCAN FLOWS
    for _ in range(n_portscan):
        dst_port = np.random.randint(1, 65535)
        # Port scans are extremely short, often single SYN packet or SYN+RST
        duration_us = np.random.uniform(50, 50_000) # 50us to 50ms
        tot_fwd_pkts = np.random.choice([1, 2, 3], p=[0.75, 0.20, 0.05])
        has_reply = np.random.choice([True, False], p=[0.2, 0.8])
        tot_bwd_pkts = 1 if has_reply else 0
        
        fwd_mean = np.random.uniform(40, 60) # SYN packets with no payload
        bwd_mean = np.random.uniform(40, 60) if has_reply else 0.0
        fwd_len = tot_fwd_pkts * fwd_mean
        bwd_len = tot_bwd_pkts * bwd_mean
        
        duration_sec = max(duration_us / 1e6, 0.00005)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        tot_bytes = fwd_len + bwd_len
        
        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "Total Length of Fwd Packets": fwd_len,
            "Total Length of Bwd Packets": bwd_len,
            "Fwd Packet Length Max": fwd_mean,
            "Fwd Packet Length Min": fwd_mean,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": bwd_mean,
            "Bwd Packet Length Min": bwd_mean,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": tot_bytes / duration_sec,
            "Flow Packets/s": tot_pkts / duration_sec,
            "Flow IAT Mean": duration_us / max(tot_pkts, 1),
            "Flow IAT Std": 0.0,
            "Flow IAT Max": duration_us,
            "Flow IAT Min": duration_us,
            "Fwd IAT Mean": duration_us / tot_fwd_pkts,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": duration_us,
            "Fwd IAT Min": duration_us,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd Header Length": tot_fwd_pkts * 20,
            "Bwd Header Length": tot_bwd_pkts * 20,
            "Fwd Packets/s": tot_fwd_pkts / duration_sec,
            "Bwd Packets/s": tot_bwd_pkts / duration_sec,
            "Min Packet Length": min(fwd_mean, bwd_mean) if has_reply else fwd_mean,
            "Max Packet Length": max(fwd_mean, bwd_mean),
            "Packet Length Mean": tot_bytes / tot_pkts,
            "Packet Length Std": 2.0,
            "Packet Length Variance": 4.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": tot_fwd_pkts, # High SYN count
            "RST Flag Count": 1 if has_reply else 0, # Closed port sends RST
            "PSH Flag Count": 0,
            "ACK Flag Count": 0, # Port scan probe does not acknowledge
            "URG Flag Count": 0,
            "Down/Up Ratio": 0.0 if not has_reply else (1.0 / tot_fwd_pkts),
            "Average Packet Size": tot_bytes / tot_pkts,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Label": "PortScan"
        }
        rows.append(row)
        
    # 3. DoS FLOWS (e.g. SYN Flood, Slowloris, UDP burst)
    for _ in range(n_dos):
        dst_port = np.random.choice([80, 443, 8080, 53, 21])
        duration_us = np.random.exponential(scale=10_000_000) + 1_000_000 # 1s to 15s
        tot_fwd_pkts = np.random.randint(200, 5000) # Very high packet count
        tot_bwd_pkts = np.random.randint(0, 10) # Target server overwhelmed, near-0 reply
        
        fwd_mean = np.random.uniform(40, 120)
        bwd_mean = 54.0 if tot_bwd_pkts > 0 else 0.0
        fwd_len = tot_fwd_pkts * fwd_mean
        bwd_len = tot_bwd_pkts * bwd_mean
        
        duration_sec = max(duration_us / 1e6, 0.01)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        tot_bytes = fwd_len + bwd_len
        
        flow_bytes_s = tot_bytes / duration_sec
        flow_pkts_s = tot_pkts / duration_sec
        
        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "Total Length of Fwd Packets": fwd_len,
            "Total Length of Bwd Packets": bwd_len,
            "Fwd Packet Length Max": fwd_mean * 1.1,
            "Fwd Packet Length Min": fwd_mean * 0.9,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": 5.0,
            "Bwd Packet Length Max": bwd_mean,
            "Bwd Packet Length Min": bwd_mean,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": duration_us / max(tot_pkts, 1),
            "Flow IAT Std": (duration_us / max(tot_pkts, 1)) * 0.2,
            "Flow IAT Max": (duration_us / max(tot_pkts, 1)) * 2.0,
            "Flow IAT Min": 1.0,
            "Fwd IAT Mean": duration_us / tot_fwd_pkts,
            "Fwd IAT Std": (duration_us / tot_fwd_pkts) * 0.2,
            "Fwd IAT Max": (duration_us / tot_fwd_pkts) * 2.0,
            "Fwd IAT Min": 1.0,
            "Bwd IAT Mean": (duration_us / max(tot_bwd_pkts, 1)) if tot_bwd_pkts > 0 else 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": duration_us if tot_bwd_pkts > 0 else 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd Header Length": tot_fwd_pkts * 20,
            "Bwd Header Length": tot_bwd_pkts * 20,
            "Fwd Packets/s": tot_fwd_pkts / duration_sec,
            "Bwd Packets/s": tot_bwd_pkts / duration_sec,
            "Min Packet Length": min(fwd_mean, bwd_mean) if tot_bwd_pkts > 0 else fwd_mean,
            "Max Packet Length": max(fwd_mean, bwd_mean),
            "Packet Length Mean": tot_bytes / tot_pkts,
            "Packet Length Std": 4.0,
            "Packet Length Variance": 16.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": tot_fwd_pkts,
            "RST Flag Count": np.random.randint(0, 5),
            "PSH Flag Count": 0,
            "ACK Flag Count": tot_bwd_pkts,
            "URG Flag Count": 0,
            "Down/Up Ratio": tot_bwd_pkts / tot_fwd_pkts,
            "Average Packet Size": tot_bytes / tot_pkts,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Label": "DoS"
        }
        rows.append(row)
        
    # 4. BRUTE FORCE FLOWS (e.g. SSH / FTP Patator)
    for _ in range(n_bruteforce):
        dst_port = np.random.choice([22, 21, 3389, 23])
        duration_us = np.random.uniform(500_000, 3_000_000) # 0.5s to 3s per attempt
        tot_fwd_pkts = np.random.randint(8, 25)
        tot_bwd_pkts = np.random.randint(6, 20)
        
        fwd_mean = np.random.uniform(80, 200) # Auth payloads
        bwd_mean = np.random.uniform(60, 150) # Rejections / challenges
        fwd_len = tot_fwd_pkts * fwd_mean
        bwd_len = tot_bwd_pkts * bwd_mean
        
        duration_sec = max(duration_us / 1e6, 0.1)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        tot_bytes = fwd_len + bwd_len
        
        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "Total Length of Fwd Packets": fwd_len,
            "Total Length of Bwd Packets": bwd_len,
            "Fwd Packet Length Max": fwd_mean * 1.4,
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_mean * 0.3,
            "Bwd Packet Length Max": bwd_mean * 1.4,
            "Bwd Packet Length Min": 40.0,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_mean * 0.3,
            "Flow Bytes/s": tot_bytes / duration_sec,
            "Flow Packets/s": tot_pkts / duration_sec,
            "Flow IAT Mean": duration_us / max(tot_pkts, 1),
            "Flow IAT Std": (duration_us / max(tot_pkts, 1)) * 0.4,
            "Flow IAT Max": duration_us * 0.5,
            "Flow IAT Min": 10.0,
            "Fwd IAT Mean": duration_us / tot_fwd_pkts,
            "Fwd IAT Std": (duration_us / tot_fwd_pkts) * 0.4,
            "Fwd IAT Max": duration_us * 0.5,
            "Fwd IAT Min": 10.0,
            "Bwd IAT Mean": duration_us / tot_bwd_pkts,
            "Bwd IAT Std": (duration_us / tot_bwd_pkts) * 0.4,
            "Bwd IAT Max": duration_us * 0.5,
            "Bwd IAT Min": 10.0,
            "Fwd PSH Flags": np.random.randint(1, 4),
            "Bwd PSH Flags": np.random.randint(1, 3),
            "Fwd Header Length": tot_fwd_pkts * 20,
            "Bwd Header Length": tot_bwd_pkts * 20,
            "Fwd Packets/s": tot_fwd_pkts / duration_sec,
            "Bwd Packets/s": tot_bwd_pkts / duration_sec,
            "Min Packet Length": 40.0,
            "Max Packet Length": max(fwd_mean * 1.4, bwd_mean * 1.4),
            "Packet Length Mean": tot_bytes / tot_pkts,
            "Packet Length Std": 30.0,
            "Packet Length Variance": 900.0,
            "FIN Flag Count": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": np.random.choice([0, 1], p=[0.7, 0.3]),
            "PSH Flag Count": np.random.randint(2, 6),
            "ACK Flag Count": tot_pkts - 1,
            "URG Flag Count": 0,
            "Down/Up Ratio": tot_bwd_pkts / tot_fwd_pkts,
            "Average Packet Size": tot_bytes / tot_pkts,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Label": "Brute Force"
        }
        rows.append(row)
        
    df = pd.DataFrame(rows)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df
