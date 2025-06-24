from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
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
        ip = packet.find(ipv4)

        if not ip:
            log.debug("Paquete no es IP, se ignora.")
            return

        src_ip = str(ip.srcip)
        dst_ip = str(ip.dstip)
        proto = ip.protocol  # 1: ICMP, 6: TCP, 17: UDP
        action_taken = None

        for rule in self.rules:
            if rule["src_ip"] == src_ip and rule["dst_ip"] == dst_ip:
                if rule["protocol"] == "ICMP" and proto == ipv4.ICMP_PROTOCOL:
                    action_taken = rule["action"]
                    break
                if rule["protocol"] == "TCP" and proto == ipv4.TCP_PROTOCOL:
                    tcp_seg = packet.find(tcp)
                    if tcp_seg and rule.get("dst_port") == tcp_seg.dstport:
                        action_taken = rule["action"]
                        break

        if action_taken == "deny":
            log.info("Tráfico bloqueado: %s -> %s (%s)", src_ip, dst_ip, rule["protocol"])
            return

        # Por defecto o si es "allow"
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    core.registerNew(Firewall)
