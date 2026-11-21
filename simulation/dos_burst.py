"""
NetSentinel AI - Controlled Lab Simulation: DoS Flood Simulator
Generates a short burst of rapid connection requests or UDP datagrams
to simulate high-volume resource exhaustion patterns.
"""

import sys
import time
import socket

def run_dos_burst(target_ip: str = "127.0.0.1", target_port: int = 80, burst_count: int = 150):
    print(f"[Sim DoS] Triggering burst of {burst_count} rapid packets to {target_ip}:{target_port}...")
    
    for i in range(burst_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            s.connect_ex((target_ip, target_port))
            s.close()
        except Exception:
            pass
        if i % 30 == 0:
            print(f"  Sent {i}/{burst_count} flood packets...")
            
    print(f"[Sim DoS] Flood burst completed. Check NetSentinel AI Dashboard for 'DoS' alert.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_dos_burst(target)
