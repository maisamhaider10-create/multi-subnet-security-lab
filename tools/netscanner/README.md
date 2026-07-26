# netscanner

A simple multi-threaded Python subnet/port scanner. Built as a learning project to understand sockets, concurrency, and CLI tooling in Python.

## What it does

Given a subnet (e.g. `192.168.1`), the script checks every host from `.1` to `.254` against a list of ports and reports which hosts respond ("are alive") and which ports are open on them.

## Features

- Socket-based TCP connect scanning
- Multi-port scanning per host
- Multi-threaded for speed (`ThreadPoolExecutor`)
- Configurable via CLI arguments (`argparse`)

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Installation

```bash
git clone https://github.com/<your-username>/netscanner.git
cd netscanner
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
```

## Usage

```bash
python main.py --base <subnet_base> [--ports <comma_separated_ports>] [--workers <n>]
```

### Examples

Scan your local subnet on the default ports (80, 443, 445, 22, 3389):
```bash
python main.py --base 192.168.1
```

Scan specific ports:
```bash
python main.py --base 192.168.1 --ports 80,443,8080
```

Use more threads for a faster scan:
```bash
python main.py --base 192.168.1 --ports 22,3389 --workers 100
```

### Arguments

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--base` | `-b` | Base of the subnet to scan, e.g. `192.168.1` (no trailing dot) | *required* |
| `--ports` | `-p` | Comma-separated list of ports to scan | `80,443,445,22,3389` |
| `--workers` | `-w` | Number of concurrent threads | `50` |

## Example output

```
Scanning 192.168.1.1 - 192.168.1.254 on ports [80, 443, 445, 22, 3389]...

[+] 192.168.1.1 is alive (open ports: [80])
[+] 192.168.1.4 is alive (open ports: [445])

Scan complete. 2 host(s) found with at least one open port.
  192.168.1.1: [80]
  192.168.1.4: [445]
```

## ⚠️ Legal & ethical use

This tool is intended for scanning networks you own or have explicit permission to test (e.g. your own home network or a lab environment). Scanning networks without authorization may be illegal depending on your jurisdiction. Use responsibly.

## Motivation

This was built as a first project to learn:
- Python sockets and TCP connections
- Concurrency with `ThreadPoolExecutor`
- Building CLI tools with `argparse`
- Basic network scanning concepts

## Possible future improvements

- [ ] Export results to CSV/JSON
- [ ] Add UDP port scanning
- [ ] Add banner grabbing to identify services
- [ ] Progress bar for large scans
- [ ] Async version using `asyncio`

## License

MIT
