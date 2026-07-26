# Multi-Subnet Security Lab

A hands-on network security simulation built with Mininet: a 3-subnet,
2-router topology with firewall rules, intrusion detection, and a live
ARP-spoofing man-in-the-middle attack carried out and analyzed against it.

This project integrates four previously built security tools (port
scanner, packet sniffer, firewall/IDS, log analyzer) into a single working
environment, and includes an automated 5-layer test suite validating
connectivity and tool behavior end-to-end.

**Skills demonstrated:** network architecture & routing, firewall/IDS
design, traffic analysis, attack simulation (ARP spoofing MITM), Python
tooling, and test automation.

This is Project 6 in a self-driven series of cybersecurity/networking
builds, following a port scanner, packet sniffer, firewall/IDS, and a
log-analyzer/SIEM-lite tool.

---

## Architecture
' ' ' 
                ┌──────────┐         ┌──────────┐
                │    r1    │─────────│    r2    │
                │ (router) │ shared  │ (router) │
                └────┬─────┘ segment └────┬─────┘
                     │      10.0.1.0/24    │
          10.0.0.0/24│                     │10.0.2.0/24
                ┌────┴─────┐         ┌─────┴────┐
          ┌─────┴───┬──────┴───┐┌─────┴────┬─────┴────┐
          │   h1    │    h2    ││   h3     │    h4    │
          └─────────┴──────────┘└──────────┴──────────┘
                                 ┌──────────┬──────────┐
                                 │   h5     │    h6     │
                                 └──────────┴──────────┘
' ' ' 
- **2 routers** (r1, r2) connected via a shared segment (10.0.1.0/24)
- **3 subnets**, 6 hosts total (2 per subnet)
- Static routing configured between subnets (no dynamic routing protocol)
- IP forwarding enabled on both routers

---

## What This Demonstrates

### Firewall & Routing
Firewall rules were applied at the router level and validated with
`pingall` tests across all subnet pairs (56/56 successful pings after
firewall rules were correctly scoped).

### Integrated Security Tooling
Four standalone tools were integrated directly against this topology:

- **netscanner** — network/port discovery across subnets and within a
  single subnet
- **packet sniffer** — live traffic capture, including cross-subnet ICMP
- **log analyzer (SIEM-lite)** — parses tool output/logs and flags
  suspicious activity (e.g. port scans)
- **mini_ips** — lightweight intrusion detection, tested against port
  scan behavior

### Attack Simulation: ARP Spoofing MITM
An ARP spoofing man-in-the-middle attack was carried out against the
topology: attacker host `h2` impersonated `r1`'s gateway, with `h1` as
the victim. Before/after captures confirm the gateway's MAC mapping was
successfully poisoned and traffic was intercepted.

This scenario was also used to test the limits of `mini_ips` (see
[Limitations](#limitations) below).

### Automated Testing
`test_suite.py` runs a 5-layer automated test battery covering
connectivity (pingall) and all four integrated tools, with all tests
passing.

---

## Setup / Prerequisites

- Ubuntu (tested on WSL2, should work on native Ubuntu as well)
- [Mininet](http://mininet.org/) installed
- Python 3
- Root/sudo access (Mininet requires it to create virtual network
  interfaces)

```bash
sudo apt update
sudo apt install mininet python3-pip
```

---

## How to Run

Clone the repo and enter the project directory:

```bash
git clone https://github.com/maisamhaider10-create/multi-subnet-security-lab.git
cd multi-subnet-security-lab
```

Launch the topology:

```bash
sudo python3 run3.py
```

This starts the Mininet CLI with the full topology running (2 routers,
3 subnets, 6 hosts, routes and IP forwarding already configured).

From the Mininet CLI, you can test connectivity:
' ' ' 
mininet> pingall
' ' '
Or run the individual tools — see each tool's own README under
`tools/` for specific usage (`tools/netscanner/`,
`tools/project-2-packet-sniffer/`, `tools/log-analyzer-siem-lite/`,
`tools/mini_ips/`).

To run the full automated test suite instead of the interactive CLI:

```bash
sudo python3 test_suite.py
```

---

## Screenshots

See the [`screenshots/`](./screenshots) folder for the full walkthrough,
including:

- Baseline connectivity and firewall enforcement (01–05)
- Topology and routing tables (06)
- Cross-subnet traffic capture (07–08)
- Tool discovery output (09–14)
- ARP spoofing MITM attack: baseline → poisoned → IDS blind spot →
  cleanup/restore (15–22)

---

## Limitations

- **L2-only blind spot in the IDS:** `mini_ips` detects threats at
  Layer 3/4 (IP/port-based), such as port scans. The ARP spoofing MITM
  attack (Layer 2, gateway impersonation) was confirmed to go
  undetected — ARP spoofing operates below the layer this tool
  inspects. This is a known architectural gap: catching it would
  require ARP-table monitoring or a dedicated Layer 2 detection
  mechanism (e.g. tracking MAC/IP pairings for inconsistencies), which
  is a natural next step.
- **Static routing only:** no dynamic routing protocol (e.g. OSPF) is
  implemented — routes between subnets are configured manually.
- **Single-host emulation:** all hosts/routers run as Mininet nodes on
  one machine, not physically separate systems.

---

## Project Series

This is Project 6 of a self-driven cybersecurity/networking series:

1. Network scanner
2. Packet sniffer
3. Firewall / IDS
4. Log analyzer (SIEM-lite)
5. *(this repo)* Multi-subnet network simulation lab
