from collections import defaultdict
from datetime import timedelta
import argparse
from parse_ssh_log import parse_log_file as parse_ssh_log_file
from parse_winevents_log import parse_log_file as parse_winevents_log_file
import json
import csv

# --- Thresholds (tune these later based on real-world tuning/false-positive rates) ---
BRUTE_FORCE_MAX_ATTEMPTS = 5
BRUTE_FORCE_WINDOW_SECONDS = 30

SWEEP_MIN_DISTINCT_USERNAMES = 3
SWEEP_WINDOW_SECONDS = 60

OFF_HOURS_START = 6   # 6 AM
OFF_HOURS_END = 22    # 10 PM


def detect_brute_force(events):
    """Flag IPs with many failed attempts in a short time window."""
    alerts = []
    failures_by_ip = defaultdict(list)

    for e in events:
        if e["outcome"] == "failure":
            failures_by_ip[e["ip"]].append(e)

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])

        # Sliding window: check every attempt against the ones that follow it
        for i in range(len(attempts)):
            window_start = attempts[i]["timestamp"]
            window_end = window_start + timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)

            attempts_in_window = [
                a for a in attempts
                if window_start <= a["timestamp"] <= window_end
            ]

            if len(attempts_in_window) >= BRUTE_FORCE_MAX_ATTEMPTS:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "ip": ip,
                    "attempt_count": len(attempts_in_window),
                    "window_start": window_start,
                    "window_end": attempts_in_window[-1]["timestamp"],
                    "username_targeted": attempts_in_window[0]["username"],
                })
                break  # one alert per IP is enough, don't duplicate for every sliding position

    return alerts


def detect_username_sweep(events):
    """Flag IPs that attempted many distinct usernames in a short time window."""
    alerts = []
    failures_by_ip = defaultdict(list)

    for e in events:
        if e["outcome"] == "failure":
            failures_by_ip[e["ip"]].append(e)

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])

        for i in range(len(attempts)):
            window_start = attempts[i]["timestamp"]
            window_end = window_start + timedelta(seconds=SWEEP_WINDOW_SECONDS)

            attempts_in_window = [
                a for a in attempts
                if window_start <= a["timestamp"] <= window_end
            ]

            distinct_usernames = {a["username"] for a in attempts_in_window}

            if len(distinct_usernames) >= SWEEP_MIN_DISTINCT_USERNAMES:
                alerts.append({
                    "type": "USERNAME_SWEEP",
                    "ip": ip,
                    "usernames_tried": sorted(distinct_usernames),
                    "window_start": window_start,
                    "window_end": attempts_in_window[-1]["timestamp"],
                })
                break

    return alerts


def detect_off_hours_login(events):
    """Flag successful logins outside normal business hours."""
    alerts = []

    for e in events:
        if e["outcome"] == "success":
            hour = e["timestamp"].hour
            if hour < OFF_HOURS_START or hour >= OFF_HOURS_END:
                alerts.append({
                    "type": "OFF_HOURS_LOGIN",
                    "ip": e["ip"],
                    "username": e["username"],
                    "timestamp": e["timestamp"],
                })

    return alerts

def export_to_json(alerts, filepath="alerts_output.json"):
    """Write all alerts to a JSON file. Converts datetime objects to strings first."""
    serializable_alerts = []
    for alert in alerts:
        clean_alert = {}
        for key, value in alert.items():
            if hasattr(value, "isoformat"):  # datetime objects
                clean_alert[key] = value.isoformat()
            else:
                clean_alert[key] = value
        serializable_alerts.append(clean_alert)

    with open(filepath, "w") as f:
        json.dump(serializable_alerts, f, indent=4)

    print(f"Exported {len(alerts)} alert(s) to {filepath}")


def export_to_csv(alerts, filepath="alerts_output.csv"):
    """Write all alerts to a CSV file. Handles alerts with different fields gracefully."""
    if not alerts:
        print("No alerts to export.")
        return

    # Different alert types have different fields (e.g. username_targeted vs usernames_tried),
    # so we collect the union of all possible column names first.
    all_fieldnames = set()
    for alert in alerts:
        all_fieldnames.update(alert.keys())
    all_fieldnames = sorted(all_fieldnames)

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()

        for alert in alerts:
            row = {}
            for field in all_fieldnames:
                value = alert.get(field, "")  # blank if this alert type doesn't have that field
                if hasattr(value, "isoformat"):
                    value = value.isoformat()
                elif isinstance(value, list):
                    value = "; ".join(value)  # e.g. usernames_tried list -> "Ali; Haider; Maisam"
                row[field] = value
            writer.writerow(row)

    print(f"Exported {len(alerts)} alert(s) to {filepath}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect brute-force, username sweep, and off-hours login threats in auth logs."
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file to analyze"
    )
    parser.add_argument(
        "--format",
        choices=["ssh", "winevents"],
        required=True,
        help="Format of the log file: 'ssh' or 'winevents'"
    )
    args = parser.parse_args()

    if args.format == "ssh":
        events = parse_ssh_log_file(args.log)
    else:
        events = parse_winevents_log_file(args.log)

    all_alerts = (
        detect_brute_force(events)
        + detect_username_sweep(events)
        + detect_off_hours_login(events)
    )

    print(f"Analyzed {len(events)} events. Found {len(all_alerts)} alert(s):\n")

    for alert in all_alerts:
        print(f"[ALERT] {alert['type']}")
        for key, value in alert.items():
            if key != "type":
                print(f"    {key}: {value}")
        print()

    export_to_json(all_alerts)
    export_to_csv(all_alerts)