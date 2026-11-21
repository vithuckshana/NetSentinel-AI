import scapy.all as scapy
import time

print("[Test] Sniffing real live packets for 3 seconds...")
start = time.time()
pkts = scapy.sniff(timeout=3.0, store=True)
print(f"[Test] Captured {len(pkts)} REAL physical packets in {time.time()-start:.2f}s!")
for p in pkts[:5]:
    print("  ->", p.summary())
