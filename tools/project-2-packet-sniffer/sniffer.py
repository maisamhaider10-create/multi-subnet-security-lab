import argparse
from datetime import datetime
from scapy.all import conf, sniff, wrpcap, IP, TCP, UDP, ICMP
from colorama import init, Fore, Style

init(autoreset=True)  # autoreset=True means we don't need Style.RESET_ALL after every print


def parse_args():
    parser = argparse.ArgumentParser(
        description="A lightweight real-time packet sniffer and analyzer."
    )
    parser.add_argument(
        "--iface",
        type=int,
        help="Interface index to sniff on (run --list-ifaces to see options)."
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List available network interfaces and exit."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite, default)."
    )
    parser.add_argument(
        "--proto",
        choices=["tcp", "udp", "icmp"],
        help="Only capture this protocol (default: all)."
    )
    parser.add_argument(
        "--save",
        type=str,
        help="Save captured packets to this .pcap file (e.g. capture.pcap)."
    )
    return parser.parse_args()

def list_interfaces():
    print("Available interfaces:")
    conf.ifaces.show()

def process_packet(packet):
    timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"{Fore.CYAN}[{timestamp}] [TCP] {src_ip}:{sport} -> {dst_ip}:{dport}")

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"{Fore.YELLOW}[{timestamp}] [UDP] {src_ip}:{sport} -> {dst_ip}:{dport}")

        elif packet.haslayer(ICMP):
            print(f"{Fore.GREEN}[{timestamp}] [ICMP] {src_ip} -> {dst_ip}")

        else:
            print(f"{Fore.MAGENTA}[{timestamp}] [IP-OTHER] {src_ip} -> {dst_ip} (proto={packet[IP].proto})")

    else:
        print(f"{Fore.WHITE}{Style.DIM}[{timestamp}] [NON-IP] {packet.summary()}")


def main():
    args = parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    if args.iface is None:
        print("Error: you must specify --iface (or run --list-ifaces to see options).")
        return

    iface = conf.ifaces.dev_from_index(args.iface)

    bpf_filter = args.proto if args.proto else ""

    print(f"Sniffing on interface index {args.iface}... press Ctrl+C to stop.")
    if bpf_filter:
        print(f"Filter active: {bpf_filter}")

    captured = sniff(iface=iface, prn=process_packet, store=bool(args.save),
                      count=args.count, filter=bpf_filter)

    if args.save:
        wrpcap(args.save, captured)
        print(f"Saved {len(captured)} packets to {args.save}")

if __name__ == "__main__":
    main()