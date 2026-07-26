from mininet.topo import Topo

class RouterTopo3(Topo):
    def build(self):
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        h4 = self.addHost('h4', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254')
        h5 = self.addHost('h5', ip='10.0.2.1/24', defaultRoute='via 10.0.2.254')
        h6 = self.addHost('h6', ip='10.0.2.2/24', defaultRoute='via 10.0.2.254')

        # Routers
        r1 = self.addHost('r1')
        r2 = self.addHost('r2')

        # Switches
        s1 = self.addSwitch('s1')  # 10.0.0.0/24 side
        s2 = self.addSwitch('s2')  # 10.0.1.0/24 side (shared segment between r1 and r2)
        s3 = self.addSwitch('s3')  # 10.0.2.0/24 side

        # Host <-> switch links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)

        # Router <-> switch links
        self.addLink(r1, s1)   # r1-eth0 -> 10.0.0.0/24
        self.addLink(r1, s2)   # r1-eth1 -> 10.0.1.0/24 (shared with r2)
        self.addLink(r2, s2)   # r2-eth0 -> 10.0.1.0/24 (shared with r1)
        self.addLink(r2, s3)   # r2-eth1 -> 10.0.2.0/24

topos = {'routertopo3': (lambda: RouterTopo3())}
