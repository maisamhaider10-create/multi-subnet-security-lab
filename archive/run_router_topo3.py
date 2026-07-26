from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel
from topo3 import RouterTopo3

setLogLevel('info')

topo = RouterTopo3()
net = Mininet(topo=topo, switch=OVSBridge, controller=None)
net.start()

r1 = net.get('r1')
r2 = net.get('r2')

# --- Assign router interface IPs explicitly ---
# r1: gateway for 10.0.0.0/24, and one leg on the shared 10.0.1.0/24 segment
r1.setIP('10.0.0.254/24', intf='r1-eth0')
r1.setIP('10.0.1.253/24', intf='r1-eth1')

# r2: other leg on the shared 10.0.1.0/24 segment, and gateway for 10.0.2.0/24
r2.setIP('10.0.1.254/24', intf='r2-eth0')
r2.setIP('10.0.2.254/24', intf='r2-eth1')

# --- Enable IP forwarding on both routers ---
r1.cmd('sysctl -w net.ipv4.ip_forward=1')
r2.cmd('sysctl -w net.ipv4.ip_forward=1')

# --- Static routes: each router needs to know how to reach the subnet
#     it is NOT directly attached to, via the other router's shared-segment IP ---

# r1 doesn't know 10.0.2.0/24 directly -> send it to r2 via the shared segment
r1.cmd('ip route add 10.0.2.0/24 via 10.0.1.254')

# r2 doesn't know 10.0.0.0/24 directly -> send it to r1 via the shared segment
r2.cmd('ip route add 10.0.0.0/24 via 10.0.1.253')

net.pingAll()
CLI(net)
net.stop()
