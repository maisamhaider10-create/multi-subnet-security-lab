import subprocess
import ipaddress

DRY_RUN = True

blocked_ips = set()
handled_ips = set()   # anything we've already made a decision about — blocked OR skipped

SAFE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_safe(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in SAFE_RANGES)


def block_ip(ip):
    if ip in handled_ips:
        return  # already decided what to do with this IP, don't repeat

    if _is_safe(ip):
        print(f"[BLOCKER] Skipping {ip} — private/local range, not auto-blocking.")
        handled_ips.add(ip)
        return

    rule_name = f"mini_ips_block_{ip}"
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ]

    if DRY_RUN:
        print(f"[DRY RUN] Would block {ip} with command: {' '.join(command)}")
    else:
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            print(f"[BLOCKER] Blocked {ip} via Windows Firewall.")
        except subprocess.CalledProcessError as e:
            print(f"[BLOCKER] Failed to block {ip}: {e.stderr}")
            return

    blocked_ips.add(ip)
    handled_ips.add(ip)