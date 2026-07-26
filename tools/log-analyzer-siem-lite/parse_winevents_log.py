from datetime import datetime

LOG_FILE = "sample_logs/sample_winevents.log"


def parse_block(block_text):
    """Turn one event block of 'Key: Value' lines into a dict of raw fields."""
    raw_fields = {}

    for line in block_text.strip().splitlines():
        if ":" not in line:
            continue  # skip any stray blank/malformed line

        key, value = line.split(":", 1)  # split only on the FIRST colon
        raw_fields[key.strip()] = value.strip()

    return raw_fields


def normalize_event(raw_fields):
    """Convert raw Windows Event fields into our standard event shape."""
    event_id = raw_fields.get("Event ID")

    if event_id == "4624":
        outcome = "success"
    elif event_id == "4625":
        outcome = "failure"
    else:
        return None  # not a login event we care about (yet)

    # Example raw date: "7/24/2026 8:15:03 AM"
    timestamp = datetime.strptime(raw_fields["Date"], "%m/%d/%Y %I:%M:%S %p")

    return {
        "timestamp": timestamp,
        "username": raw_fields.get("Account Name"),
        "ip": raw_fields.get("Source Network Address"),
        "outcome": outcome,
    }


def parse_log_file(filepath):
    """Read the whole file, split into blocks, and return a list of normalized events."""
    with open(filepath, "r") as f:
        content = f.read()

    # Blocks are separated by one or more blank lines
    blocks = [b for b in content.split("\n\n") if b.strip()]

    events = []
    for block in blocks:
        raw_fields = parse_block(block)
        event = normalize_event(raw_fields)
        if event is not None:
            events.append(event)

    return events


if __name__ == "__main__":
    events = parse_log_file(LOG_FILE)

    print(f"Parsed {len(events)} events:\n")
    for e in events:
        print(e)