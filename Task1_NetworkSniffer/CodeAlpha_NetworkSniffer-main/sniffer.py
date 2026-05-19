from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)

        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"[{protocol}] {ip_layer.src} -> {ip_layer.dst}")

print("Starting packet capture...")

try:
    sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("\nStopping packet capture...")
