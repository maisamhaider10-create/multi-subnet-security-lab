import re
from datetime import datetime

LOG_FILE = "sample_logs/sample_auth.log"

# This pattern matches BOTH "Accepted password" and "Failed password" lines.
# Groups (the parts in parentheses) are what we extract.
LOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<outcome>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<ip>[\d.]+)\s+port\s+"
    r"(?P<port>\d+)\s+ssh2"
)


def parse_line(line):
    """Try to match one log line against the pattern. Return a dict or None."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()

    # Build a real datetime object so we can later do time-based comparisons.
    # We assume the current year since syslog-style timestamps don't include one.
    timestamp_str = f"{datetime.now().year} {data['month']} {data['day']} {data['time']}"
    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

    return {
        "timestamp": timestamp,
        "username": data["username"],
        "ip": data["ip"],
        "outcome": "success" if data["outcome"] == "Accepted" else "failure",
    }


def parse_log_file(filepath):
    """Read the whole file and return a list of parsed event dicts."""
    events = []
    with open(filepath, "r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue  # skip blank lines

            event = parse_line(line)
            if event is None:
                print(f"[!] Could not parse line {line_number}: {line}")
                continue

            events.append(event)
    return events


if __name__ == "__main__":
    events = parse_log_file(LOG_FILE)

    print(f"Parsed {len(events)} events:\n")
    for e in events:
        print(e)