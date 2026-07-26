
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel
from topo2 import RouterTopo

setLogLevel('info')

topo = RouterTopo()
net = Mininet(topo=topo, switch=OVSBridge, controller=None)
net.start()
r1 = net.get('r1')
r1.setIP('10.0.0.254/24', intf='r1-eth0')
r1.cmd('sysctl -w net.ipv4.ip_forward=1')

# ---Firewall rule: block h3 -> h1 specifically
# FORWARD chain = traffic passing THROUGH r1 (not addressed to r1 itself)
result = r1.cmd('iptables -A FORWARD -s 10.0.1.1 -d 10.0.0.1 -j DROP')
print("Firewall rule output:", repr(result))
r1.cmd('iptables -A FORWARD -p tcp --dport 23 -j DROP')
net.pingAll()
CLI(net)
net.stop()

