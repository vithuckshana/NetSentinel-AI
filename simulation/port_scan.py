"""
NetSentinel AI - Controlled Lab Simulation: Port Scanning Probe
Performs a rapid sequential and random port sweep against a target server
to test heuristic and machine learning intrusion detection in real-time.
"""

import sys
import time
import socket
import random

def run_port_scan(target_ip: str = "127.0.0.1", ports_to_probe: int = 15):
    print(f"[Sim PortScan] Target: {target_ip} | Scanning {ports_to_probe} ports rapidly...")
    probed_ports = random.sample(range(20, 1024), ports_to_probe)
    
    for port in probed_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        res = s.connect_ex((target_ip, port))
        s.close()
        print(f"  Scanned port {port:4d} -> Result: {'OPEN' if res == 0 else 'CLOSED'}")
        time.sleep(0.02)
        
    print(f"[Sim PortScan] Probe finished. Check NetSentinel AI Dashboard for 'PortScan' alert.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_port_scan(target)
