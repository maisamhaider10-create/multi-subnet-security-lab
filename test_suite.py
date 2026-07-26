from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.log import setLogLevel
from topo3 import RouterTopo3
import time

def setup_network():
    setLogLevel('info')
    topo = RouterTopo3()
    net = Mininet(topo=topo, switch=OVSBridge, controller=None)
    net.start()

    r1 = net.get('r1')
    r2 = net.get('r2')

    r1.setIP('10.0.0.254/24', intf='r1-eth0')
    r1.setIP('10.0.1.253/24', intf='r1-eth1')
    r2.setIP('10.0.1.254/24', intf='r2-eth0')
    r2.setIP('10.0.2.254/24', intf='r2-eth1')

    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')

    r1.cmd('ip route add 10.0.2.0/24 via 10.0.1.254')
    r2.cmd('ip route add 10.0.0.0/24 via 10.0.1.253')

    return net

def test_connectivity(net):
    print("\n=== TEST LAYER 1: Connectivity ===")
    dropped = net.pingAll()
    if dropped == 0:
        print("PASS: full connectivity, 0% packet loss")
    else:
        print(f"FAIL: {dropped}% packet loss")
    return dropped == 0

def test_netscanner(net):
    print("\n=== TEST LAYER 2a: Netscanner smoke test ===")
    h1 = net.get('h1')
    h2 = net.get('h2')

    h2.cmd('python3 -m http.server 8080 &> /tmp/http_test.log &')
    time.sleep(2)

    result = h1.cmd(
        'cd /home/maisam/network-lab/tools/netscanner && '
        'python3 main.py --base 10.0.0 --ports 8080 --workers 5'
    )
    print(result)

    h2.cmd('pkill -f "http.server 8080"')

    passed = '10.0.0.2' in result and '8080' in result
    if passed:
        print("PASS: netscanner found the known open port on h2")
    else:
        print("FAIL: netscanner did not detect the expected open port")
    return passed

def test_sniffer(net):
    print("\n=== TEST LAYER 2b: Sniffer smoke test ===")
    h1 = net.get('h1')
    h2 = net.get('h2')

    sniffer_dir = '/home/maisam/network-lab/tools/project-2-packet-sniffer'

    ifaces = h1.cmd(f'cd {sniffer_dir} && python3 sniffer.py --list-ifaces')
    print("Interfaces on h1:\n", ifaces)

    # h1's Mininet interface is always h1-eth0 - find its listed index
    iface_index = None
    for line in ifaces.splitlines():
        if 'h1-eth0' in line:
            iface_index = line.strip().split()[1]
            break

    if iface_index is None:
        print("FAIL: could not find h1-eth0 in --list-ifaces output")
        return False

    print(f"Using iface index: {iface_index}")

    # start capture in background, then generate ICMP traffic to sniff
    h1.cmd(
        f'cd {sniffer_dir} && python3 sniffer.py --iface {iface_index} '
        f'--proto icmp --count 3 --save /tmp/sniff_test.pcap &> /tmp/sniff_test.log &'
    )
    import time
    time.sleep(1)
    h1.cmd('ping -c 3 10.0.0.2')
    time.sleep(2)

    log = h1.cmd('cat /tmp/sniff_test.log')
    print("Sniffer log:\n", log)

    pcap_check = h1.cmd('stat -c %s /tmp/sniff_test.pcap 2>/dev/null || echo 0')
    pcap_size = int(pcap_check.strip().splitlines()[-1])
    print(f"Captured .pcap file size: {pcap_size} bytes")

    passed = pcap_size > 0 and 'error' not in log.lower()
    if passed:
        print("PASS: sniffer captured ICMP traffic and wrote a non-empty pcap")
    else:
        print("FAIL: sniffer did not produce a valid capture")
    return passed

def test_log_analyzer(net):
    print("\n=== TEST LAYER 2c: Log-analyzer smoke test ===")
    h1 = net.get('h1')

    analyzer_dir = '/home/maisam/network-lab/tools/log-analyzer-siem-lite'

    result = h1.cmd(
        f'cd {analyzer_dir} && '
        f'python3 detect_threats.py --log sample_logs/sample_auth.log --format ssh'
    )
    print(result)

    expected_alerts = ['BRUTE_FORCE', 'USERNAME_SWEEP', 'OFF_HOURS_LOGIN']
    found = [alert for alert in expected_alerts if alert in result]
    missing = [alert for alert in expected_alerts if alert not in found]

    passed = len(missing) == 0
    if passed:
        print(f"PASS: all {len(expected_alerts)} expected alert types fired")
    else:
        print(f"FAIL: missing alert type(s): {missing}")
    return passed
def test_mini_ips(net):
    print("\n=== TEST LAYER 2d: Mini-IPS smoke test ===")
    r1 = net.get('r1')
    h1 = net.get('h1')

    ips_dir = '/home/maisam/network-lab/tools/mini_ips'

    # mini_ips has no CLI args - it sniffs all interfaces by default,
    # so we run it directly on r1 to see traffic crossing both subnets
    r1.cmd(f'cd {ips_dir} && python3 -u main.py &> /tmp/mini_ips_test.log &')
    time.sleep(1)

    # Trigger 1: BAD_PORT - single connection attempt to a known-bad port
    h1.cmd('nc -zv 10.0.0.254 23')
    time.sleep(1)

    # Trigger 2: PORT_SCAN - 10+ distinct ports via SYN scan inside the 5s window
    h1.cmd('/usr/bin/nmap -sS -p 1-20 --min-rate 100 10.0.0.254')
    time.sleep(2)

    log = r1.cmd('cat /tmp/mini_ips_test.log')
    print("Mini-IPS log:\n", log)

    r1.cmd('pkill -f "python3 main.py"')

    expected_alerts = ['BAD_PORT', 'PORT_SCAN']
    found = [alert for alert in expected_alerts if alert in log]
    missing = [alert for alert in expected_alerts if alert not in found]

    passed = len(missing) == 0
    if passed:
        print(f"PASS: all {len(expected_alerts)} expected alert types fired")
    else:
        print(f"FAIL: missing alert type(s): {missing}")
    return passed

if __name__ == '__main__':
    net = setup_network()
    try:
        test_connectivity(net)
        test_netscanner(net)
        test_sniffer(net)
        test_log_analyzer(net)
        test_mini_ips(net)
    finally:
        net.stop()