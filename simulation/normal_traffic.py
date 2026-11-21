"""
NetSentinel AI - Controlled Lab Simulation: Normal Traffic Generator
Emulates legitimate HTTP, DNS, and HTTPS communications with standard TCP handshakes.
"""

import time
import socket
import random
import requests

TARGET_HOSTS = ["1.1.1.1", "8.8.8.8"]

def run_normal_simulation(iterations: int = 10, delay_sec: float = 1.0):
    print(f"[Sim Normal] Starting legitimate traffic emulation ({iterations} cycles)...")
    for i in range(iterations):
        target = random.choice(TARGET_HOSTS)
        port = random.choice([53, 80, 443])
        print(f"  Cycle {i+1}/{iterations}: Legitimate connection to {target}:{port}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
        time.sleep(delay_sec)
    print("[Sim Normal] Legitimate simulation completed.")

if __name__ == "__main__":
    run_normal_simulation()
