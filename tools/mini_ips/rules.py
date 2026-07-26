import tracker

# ---- Thresholds (tune these as you test) ----
PORT_SCAN_WINDOW = 5          # seconds
PORT_SCAN_THRESHOLD = 10      # distinct ports within window = scan

FLOOD_WINDOW = 5
FLOOD_THRESHOLD = 100    # was 30 — tuned up after testing against normal browsing traffic

# Ports commonly associated with backdoors/trojans/insecure services.
# Not exhaustive — a small illustrative starter set.
BAD_PORTS = {23, 2323, 4444, 31337, 12345, 6667}


def evaluate_packet(info):
    src_ip = info["src_ip"]
    dst_port = info["dst_port"]
    flags = info["flags"]

    # Only treat bare SYN packets (new connection attempts) as scan/flood
    # signal. Ignore replies, ACKs, and established-connection data —
    # those come from normal traffic and would create false positives
    # (e.g. a server's reply packets using your random ephemeral ports
    # looking like "many distinct ports" when it's not scanning at all).
    is_new_connection_attempt = (flags == "S")

    if is_new_connection_attempt:
        tracker.record_event(src_ip, dst_port)

    alerts = []

    if is_new_connection_attempt:
        distinct_ports = tracker.get_distinct_port_count(src_ip, PORT_SCAN_WINDOW)
        if distinct_ports >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "detail": f"{distinct_ports} distinct ports in {PORT_SCAN_WINDOW}s",
            })

        total_conns = tracker.get_connection_count(src_ip, FLOOD_WINDOW)
        if total_conns >= FLOOD_THRESHOLD:
            alerts.append({
                "type": "CONNECTION_FLOOD",
                "src_ip": src_ip,
                "detail": f"{total_conns} connections in {FLOOD_WINDOW}s",
            })

    # Bad-port check stays independent of SYN filtering — any traffic
    # to/from a known-bad port is worth flagging regardless of direction.
    if dst_port in BAD_PORTS:
        alerts.append({
            "type": "BAD_PORT",
            "src_ip": src_ip,
            "detail": f"connection to suspicious port {dst_port}",
        })

    return alerts