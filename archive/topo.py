from mininet.topo import Topo

class MyTopo(Topo):
	def build(self):
		# Add switches
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		


		#add hosts on segment 1
		h1 = self.addHost('h1', ip='10.0.0.1/24')
		h2 = self.addHost('h2', ip='10.0.0.2/24')

		#Add hosts on segment 2
		h3 = self.addHost('h3', ip='10.0.0.3/24')
		h4 = self.addHost('h4', ip='10.0.0.4/24')

		#Link hosts to their switch
		self.addLink(h1, s1)
		self.addLink(h2, s1)
		self.addLink(h3, s2)
		self.addLink(h4, s2)

		#Link hosts to their switch
		self.addLink(s1, s2)

topos = {'mytopo' : MyTopo}
