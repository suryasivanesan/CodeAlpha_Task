from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = ""
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = ip_layer.proto

        print(f"Source: {ip_layer.src} --> Destination: {ip_layer.dst} | Protocol: {proto}")
        payload = bytes(packet.payload)
        print(f"Payload (truncated): {payload[:32]}...\n")

# Start sniffing
sniff(prn=process_packet, store=False)
