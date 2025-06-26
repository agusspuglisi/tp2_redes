from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv6 import ipv6
import json
import os

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.rules = self.load_rules()
        log.info("Firewall avanzado iniciado")

    def load_rules(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        rules_path = os.path.join(project_root, 'rules.json')
        try:
            with open(rules_path, 'r') as f:
                rules = json.load(f)
                log.debug("Reglas cargadas: %s", rules)
                return rules
        except Exception as e:
            log.error("Error al cargar rules.json: %s", e)
            return []

    def _handle_ConnectionUp(self, event):
        log.info("Conexión establecida con switch %s", event.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port

        log.debug("PacketIn recibido en switch %s (puerto %s)", dpid, in_port)

        eth = packet.find(ethernet)

        if not eth:
            return  # No es un paquete Ethernet, ignorar
        
        src_mac = str(eth.src)
        dst_mac = str(eth.dst)

        ip_pkt = packet.find(ipv4) or packet.find(ipv6)
        if not ip_pkt:
            log.debug("Paquete no es IP, se ignora.")
            return
        
        tcp_pkt = packet.find(tcp)
        udp_pkt = packet.find(udp)

        action = "allow"  # Acción por defecto

        for rule in self.rules:
            # Regla de bloqueo total entre hosts específicos (por IP)
            if "host_a" in rule and "host_b" in rule:
                hosts = [rule["host_a"], rule["host_b"]]
                if ip_pkt and (str(ip_pkt.srcip) in hosts and str(ip_pkt.dstip) in hosts):
                    action = rule["action"]
                    log.debug("Regla bloque total aplicada: %s", rule)
                    log.debug("Hosts involucrados: %s", hosts)
                    break
            # Bloqueo puerto destino 80
            elif rule.get("dst_port") == 80 and (tcp_pkt or udp_pkt):
                action = rule["action"]
                log.debug("Regla puerto 80 aplicada: %s", rule)
                log.debug("Hosts involucrados: %s", hosts)
                break
            # Bloqueo UDP de host específico hacia puerto 5001
            elif udp_pkt and rule.get("protocol") == "udp" and rule.get("dst_port") == udp_pkt.dstport:
                if (str(ip_pkt.srcip) == rule.get("src_host") and udp_pkt.dstport == rule.get("dst_port")):
                    action = rule["action"]
                    log.debug("Regla aplicada: %s", rule)
                    log.debug("Hosts involucrados: %s", hosts)
                    break

        if action == "deny":
            log.info("Insertando regla de bloqueo MAC en switch")
            msg = of.ofp_flow_mod()
            msg.match.dl_src = eth.src
            msg.match.dl_dst = eth.dst
            msg.actions = []  
            event.connection.send(msg)
            log.info("Tráfico bloqueado desde %s hacia %s (MAC)", src_mac, dst_mac)
            return

        # Por defecto o si es "allow"
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    core.registerNew(Firewall)

# iperf -s -u -p 5001
# iperf -c 10.0.0.2 -u -p 5001