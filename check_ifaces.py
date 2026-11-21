from scapy.all import get_if_list, get_working_if, conf
print("Default working interface:", get_working_if())
print("\nAll available interfaces:")
for i, iface in enumerate(get_if_list()):
    print(f"  [{i}] {iface}")
