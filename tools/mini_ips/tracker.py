from collections import defaultdict, deque
import time

# For each source IP, store a deque of (timestamp, dst_port) events.
activity = defaultdict(deque)


def record_event(src_ip, dst_port):
    """
    Log a new connection attempt from src_ip to dst_port, timestamped now.
    """
    now = time.time()
    activity[src_ip].append((now, dst_port))


def _expire_old(src_ip, window_seconds):
    """
    Remove events older than window_seconds from this IP's deque.
    Internal helper — called before we answer any query.
    """
    now = time.time()
    events = activity[src_ip]
    while events and (now - events[0][0]) > window_seconds:
        events.popleft()


def get_connection_count(src_ip, window_seconds):
    """
    Total connection attempts from src_ip within the last window_seconds.
    """
    _expire_old(src_ip, window_seconds)
    return len(activity[src_ip])


def get_distinct_port_count(src_ip, window_seconds):
    """
    Number of DISTINCT destination ports src_ip has hit within window_seconds.
    """
    _expire_old(src_ip, window_seconds)
    ports = {port for (_, port) in activity[src_ip]}
    return len(ports)


def cleanup_all(window_seconds):
    """
    Housekeeping: expire old events across ALL tracked IPs, and drop IPs
    with no remaining events. Call this periodically so memory doesn't
    grow forever with stale/inactive IPs.
    """
    now = time.time()
    dead_ips = []
    for ip, events in activity.items():
        while events and (now - events[0][0]) > window_seconds:
            events.popleft()
        if not events:
            dead_ips.append(ip)
    for ip in dead_ips:
        del activity[ip]