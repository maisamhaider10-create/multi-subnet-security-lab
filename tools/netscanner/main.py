import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_host(ip, port, timeout=1):
    """
    Tries to connect to a given IP on a given port.
    Returns True if the host responds (is alive), False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_host_multi(ip, ports):
    """
    Checks a single host against a list of ports.
    Returns a list of open ports on that host.
    """
    open_ports = []
    for port in ports:
        if check_host(ip, port):
            open_ports.append(port)
    return open_ports


def scan_subnet(base_ip, ports, max_workers=50):
    """
    base_ip should look like '192.168.18' (no trailing dot, no last number)
    Scans .1 through .254 for the given list of ports, using threads.
    Returns a dict: {ip: [open_ports]}
    """
    alive_hosts = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_host_multi, f"{base_ip}.{last_octet}", ports): f"{base_ip}.{last_octet}"
            for last_octet in range(1, 255)
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                open_ports = future.result()
                if open_ports:
                    print(f"[+] {ip} is alive (open ports: {open_ports})")
                    alive_hosts[ip] = open_ports
            except Exception as e:
                print(f"[!] Error scanning {ip}: {e}")

    return alive_hosts


def parse_args():
    parser = argparse.ArgumentParser(
        description="A simple multi-threaded subnet/port scanner."
    )
    parser.add_argument(
        "--base", "-b",
        required=True,
        help="Base of the subnet to scan, e.g. 192.168.18 (no trailing dot)"
    )
    parser.add_argument(
        "--ports", "-p",
        default="80,443,445,22,3389",
        help="Comma-separated list of ports to scan (default: 80,443,445,22,3389)"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ports_to_scan = [int(p.strip()) for p in args.ports.split(",")]

    print(f"Scanning {args.base}.1 - {args.base}.254 on ports {ports_to_scan}...\n")
    results = scan_subnet(args.base, ports_to_scan, max_workers=args.workers)

    print(f"\nScan complete. {len(results)} host(s) found with at least one open port.")
    for ip, ports in results.items():
        print(f"  {ip}: {ports}")