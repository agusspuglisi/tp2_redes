from mininet.topo import Topo

class ChainTopo(Topo):
    def __init__(self, switches=2):
        # Initialize topology
        Topo.__init__(self)
        
        print("[DEBUG] Creando topologia...")
        print("[DEBUG] switches =", switches)
        
        if switches < 1:
            print("[ERROR] Cantidad de switches debe ser mayor o igual a 1!")
            exit(1)
        
        # Create switches
        switch_list = []
        for i in range(switches):
            switch_name = f's{i+1}'
            switch_list.append(self.addSwitch(switch_name))
            print(f"[DEBUG] Creado switch: {switch_name}")
        
        # Connect switches in chain
        for i in range(switches - 1):
            self.addLink(switch_list[i], switch_list[i + 1])
            print(f"[DEBUG] Conectando {switch_list[i]} con {switch_list[i + 1]}")
        
        # Create hosts - 2 hosts at each end
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        
        # Connect 2 hosts to the first switch
        self.addLink(h1, switch_list[0])
        self.addLink(h2, switch_list[0])
        
        # Connect 2 hosts to the last switch
        self.addLink(h3, switch_list[-1])
        self.addLink(h4, switch_list[-1])
        
        print(f"[DEBUG] Hosts h1 y h2 conectados al switch {switch_list[0]}")
        print(f"[DEBUG] Hosts h3 y h4 conectados al switch {switch_list[-1]}")
        print("[DEBUG] Topologia creada exitosamente")

topos = {'chain': ChainTopo}