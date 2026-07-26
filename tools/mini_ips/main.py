import time
import threading
from scapy.all import sniff, IP, TCP

import tracker
import rules
import alerts
import blocker

CLEANUP_INTERVAL = 30  # seconds — how often we sweep out stale tracker data
TRACKER_WINDOW = 60     # seconds — matches the widest window used in rules.py


def extract_packet_info(packet):
    if IP in packet and TCP in packet:
        return {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "dst_port": packet[TCP].dport,
            "flags": packet[TCP].flags,
        }
    return None


def packet_callback(packet):
    info = extract_packet_info(packet)
    if not info:
        return

    fired_alerts = rules.evaluate_packet(info)

    if fired_alerts:
        alerts.handle_alerts(fired_alerts)
        for alert in fired_alerts:
            blocker.block_ip(alert["src_ip"])


def periodic_cleanup():
    """
    Runs in the background, forever, expiring stale tracker entries
    so memory doesn't grow unbounded during long-running capture.
    """
    while True:
        time.sleep(CLEANUP_INTERVAL)
        tracker.cleanup_all(TRACKER_WINDOW)


def main():
    print("Mini IPS starting... press Ctrl+C to stop.")
    print(f"Dry run mode: {blocker.DRY_RUN}")

    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()