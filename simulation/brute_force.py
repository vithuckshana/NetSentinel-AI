"""
NetSentinel AI - Controlled Lab Simulation: Authentication Brute Force
Simulates repeated authentication handshakes and rapid credential exchanges
against standard management ports (SSH/22, FTP/21).
"""

import sys
import time
import socket

def run_brute_force(target_ip: str = "127.0.0.1", port: int = 22, attempts: int = 8):
    print(f"[Sim BruteForce] Simulating {attempts} rapid authentication attempts against {target_ip}:{port}...")
    
    for i in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((target_ip, port))
            # Send simulated auth banner request
            s.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")
        except Exception:
            pass
        finally:
            s.close()
        print(f"  Attempt {i+1}/{attempts} transmitted.")
        time.sleep(0.3)
        
    print(f"[Sim BruteForce] Completed attempts. Check NetSentinel AI Dashboard for 'Brute Force' alert.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_brute_force(target)
