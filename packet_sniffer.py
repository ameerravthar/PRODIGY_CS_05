from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "Unknown"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"[+] Packet: {protocol}")
        print(f"    From: {src_ip}")
        print(f"    To:   {dst_ip}")

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                print(f"    Payload: {payload[:50]}")  # show only first 50 chars
            except:
                print("    Payload: <non-decodable>")

        print("-" * 60)

# Start sniffing (first 10 packets, change if needed)
print("🔍 Sniffing started... Press CTRL+C to stop.")
sniff(prn=process_packet, count=10)