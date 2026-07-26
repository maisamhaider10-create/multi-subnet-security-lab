# Mini IPS — Lightweight Intrusion Prevention System

A simple, rule-based Intrusion Prevention System (IPS) built in Python and Scapy.
It monitors live network traffic, detects suspicious patterns (port scans, connection
floods, traffic to known-bad ports), logs alerts, and can optionally block offending
IPs via the Windows Firewall.

This is Project #3 in a progression of cybersecurity/networking tools:
1. [Network Scanner](https://github.com/maisamhaider10-create/netscanner) — host discovery + port scanning
2. [Packet Sniffer](https://github.com/maisamhaider10-create/packet-sniffer-analyzer) — live traffic capture and analysis
3. **Mini IPS** (this project) — detection + prevention, built on the same capture foundation

## What it does

- Captures live TCP traffic (via Scapy/Npcap)
- Tracks per-IP behavior over a sliding time window (stateful detection)
- Flags:
  - **Port scans** — one IP hitting many distinct ports in a short window
  - **Connection floods** — one IP making an unusually high number of connection attempts
  - **Bad-port traffic** — connections to ports commonly associated with backdoors/trojans
- Prints alerts to the terminal and logs them to `logs/alerts.log`
- Optionally blocks offending IPs using Windows Firewall (`netsh advfirewall`)

## Architecture

capture (Scapy) → tracker (stateful counting) → rules (detection logic)
↓
alerts (log/print) + blocker (netsh)

Each layer is deliberately independent:
- `tracker.py` only counts events — it has no concept of what "suspicious" means.
- `rules.py` only makes decisions — it doesn't know how packets are captured or how
  alerts get displayed.
- `alerts.py` and `blocker.py` only react to decisions already made.

This separation mirrors how real IDS/IPS tools like Suricata and Snort are structured:
a packet-decoding engine, a signature/rule engine, and an output/response layer, all
kept independent of one another.

## Stateless vs. Stateful detection

A stateless rule looks at one packet in isolation (e.g. "block anything to port 23").
A stateful rule remembers recent history for a source (e.g. "has this IP hit 10+
different ports in the last 5 seconds?"). Port scans and floods are only detectable
statefully — no single packet in a scan looks abnormal on its own; the pattern only
emerges over time. `tracker.py` implements this using per-IP sliding time windows.

## Safety design

- **Dry-run mode by default** (`DRY_RUN = True` in `blocker.py`) — the tool shows
  exactly what firewall command it *would* run, without making real changes, until
  you explicitly disable it.
- **Private/local IP ranges are never auto-blocked** (e.g. your own subnet, loopback),
  preventing the tool from accidentally blocking legitimate local traffic.
- **Alert cooldown** — the same alert type/IP pair won't re-fire on every packet while
  a condition remains true, to avoid alert fatigue (a real problem SOC analysts deal
  with when detection rules are too noisy).

## Known limitation: self-to-self traffic

Windows does not route traffic between a machine and itself (including `127.0.0.1`
and even the machine's own real IP) through the network interface that Npcap
captures on — it's handled internally by the OS and never reaches the capture layer.
This means the tool cannot be fully tested by scanning your own machine from itself.

To validate detection logic end-to-end despite this, a synthetic test harness
(`test_rules.py`, not included in this repo / included for reference) feeds
realistic simulated packet data directly into the detection pipeline, bypassing
capture entirely. This confirmed the tracker, rules, alerting, and dry-run blocking
all function correctly. Real-world testing would require traffic from a genuinely
separate device on the same network.

## Setup

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

Requires [Npcap](https://npcap.com/) installed (same as Project #2).

**Must run as Administrator** — packet capture requires elevated privileges on Windows.

## Usage

python main.py

Runs continuously until `Ctrl+C`. Alerts print to the terminal and are appended to
`logs/alerts.log`.

To enable real blocking (not just dry-run), set `DRY_RUN = False` in `blocker.py`.
**Use with caution** — this will modify your live Windows Firewall rules.

## Tuning

Detection thresholds live in `rules.py` and were tuned against real personal browsing
traffic to reduce false positives:

| Setting | Value | Notes |
|---|---|---|
| `PORT_SCAN_THRESHOLD` | 10 distinct ports / 5s | |
| `FLOOD_THRESHOLD` | 100 connections / 5s | Raised from an initial 30 after normal browsing triggered false alarms |

This is a real part of deploying detection systems — thresholds are tuned against a
traffic baseline, not set once and forgotten.

## Disclaimer

Built for learning purposes. Test only against your own machine/network. Do not
point this at networks you don't own or have explicit permission to monitor.