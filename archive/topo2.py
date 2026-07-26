from mininet.topo import Topo

class RouterTopo(Topo):
	def build(self):
		# Add router (just a host with IP fowarding + two interfaces)
		r1 = self.addHost('r1')

		# Add switches - one per subnet
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')

		# Subnet A hosts (10.0.0.0/24) - gateway will be r1's s1-facing IP
		h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
		h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')

		# Subnet B hosts (10.0.1.0/24) - gateway will be r1's s2-facing IP
		h3 = self.addHost('h3', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
		h4 = self.addHost('h4', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254')

 		# Link hosts to their subnet's switch
		self.addLink(h1, s1)
		self.addLink(h2, s1)
		self.addLink(h3, s2)
		self.addLink(h4, s2)

		# Link router to BOTH switches - giving it one leg in each subnet
		self.addLink(r1, s1, intfName1='r1-eth0', params1={'ip': '10.0.0.254/24'})
		self.addLink(r1, s2, intfName1='r1-eth1', params1={'ip': '10.0.1.254/24'})

		topos = {'routertopo' : RouterTopo}

