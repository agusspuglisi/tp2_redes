# Archivo: topo/topologia.py
from mininet.topo import Topo

class BasicTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(h2, s1)

topos = {'basic': BasicTopo}
