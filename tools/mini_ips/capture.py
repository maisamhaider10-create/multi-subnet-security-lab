from scapy.all import sniff, IP, TCP

def extract_packet_info(packet):
    """
    Pulls out the field we care about from a raw packet.
    Returns None if the packet isn't IP/TCP (we don't care anything else yet)
    """
    if IP in packet and TCP in packet:
        info = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "dst_port": packet[TCP].dport,
            "flags": packet[TCP].flags,
        }
        return info
    return None

def packet_callback(packet):
    info = extract_packet_info(packet)
    if info:
        print(f"[{info['src_ip']} -> {info['dst_ip']}] port {info['dst_port']} flags={info['flags']}")

if __name__ == "__main__":
    print("Starting capture... press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)