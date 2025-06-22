from mininet.topo import Topo

class ChainTopo(Topo):
    def build(self, n=3):
        if n < 1:
            raise Exception("La cantidad de switches debe ser >= 1")

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        switches = []
        for i in range(n):
            switch = self.addSwitch(f's{i+1}')
            switches.append(switch)

        self.addLink(h1, switches[0])

        for i in range(n - 1):
            self.addLink(switches[i], switches[i + 1])

        self.addLink(h2, switches[-1])

topos = { 'chain': ChainTopo }
