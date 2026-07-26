import time
from datetime import datetime

LOG_FILE = "logs/alerts.log"

# Prevents the same alert (same type + same IP) from re-firing every
# single packet while the condition remains true. This is the alert
# fatigue problem in miniature.
ALERT_COOLDOWN = 10  # seconds
_last_alert_time = {}  # key: (alert_type, src_ip) -> last time we alerted


def _should_fire(alert_type, src_ip):
    key = (alert_type, src_ip)
    now = time.time()
    last = _last_alert_time.get(key, 0)
    if now - last >= ALERT_COOLDOWN:
        _last_alert_time[key] = now
        return True
    return False


def handle_alerts(alerts):
    """
    Takes a list of alert dicts from rules.py and processes each one:
    prints to terminal (if not on cooldown) and logs to file.
    """
    for alert in alerts:
        if _should_fire(alert["type"], alert["src_ip"]):
            _print_alert(alert)
            _log_to_file(alert)


def _print_alert(alert):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[ALERT {timestamp}] {alert['type']} — {alert['src_ip']} — {alert['detail']}")


def _log_to_file(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {alert['type']} | {alert['src_ip']} | {alert['detail']}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)