from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.ipv6 import ipv6
import json
import os

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.rules = self.load_rules()
        self.mac_to_port = {}
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

    def _handle_PacketIn(self, event):
        """Evalúa las reglas y, de ser necesario, instala flujos de bloqueo en el switch"""
        packet = event.parsed
        eth = packet.find(ethernet)
        if not eth:
            return  # No Ethernet ⇒ ignorar
        
        dpid = event.connection.dpid

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        # Actualiza la tabla de direcciones MAC
        self.mac_to_port[dpid][eth.src] = event.port

        ip_pkt  = packet.find(ipv4) or packet.find(ipv6)
        tcp_pkt = packet.find(tcp)
        udp_pkt = packet.find(udp)

        action     = "allow"
        deny_bidir = False   # sólo true para la regla de bloqueo total entre dos hosts

        for rule in self.rules:
            # ---------------- Regla 3 : bloqueo total entre dos hosts ----------------
            if "host_a" in rule and "host_b" in rule and ip_pkt:
                s = str(ip_pkt.srcip); d = str(ip_pkt.dstip)
                if (s == rule["host_a"] and d == rule["host_b"]) or \
                   (s == rule["host_b"] and d == rule["host_a"]):
                    action     = rule["action"]
                    deny_bidir = True  # bloqueo en ambos sentidos
                    log.debug("Regla bloqueo total entre hosts aplicada: %s", rule)
                    break

            # ---------------- Regla 1 : puerto 80 ----------------
            if rule.get("dst_port") == 80:
                pkt_port = tcp_pkt.dstport if tcp_pkt else (udp_pkt.dstport if udp_pkt else None)
                if pkt_port == 80:   # coincide realmente
                    action = rule["action"]
                    log.debug("Regla delpuerto 80 aplicada: %s", rule)
                    break

            # ---------------- Regla 2 : UDP h1 → puerto 5001 ----------------
            if rule.get("protocol", "").lower() == "udp" and udp_pkt:
                if (udp_pkt.dstport == rule.get("dst_port") and ip_pkt and
                    str(ip_pkt.srcip) == rule.get("src_host")):
                    fm = of.ofp_flow_mod()
                    fm.match.dl_type   = 0x0800            # IPv4
                    fm.match.nw_proto  = 17                # UDP
                    fm.match.nw_src    = ip_pkt.srcip      # 10.0.0.1
                    fm.match.nw_dst    = ip_pkt.dstip      # 10.0.0.3
                    fm.match.tp_src    = udp_pkt.srcport
                    fm.match.tp_dst    = udp_pkt.dstport   # 5001

                    event.connection.send(fm)
                    log.info("Instalado flujo de DROP para UDP %s:%s → %s:%s", ip_pkt.srcip, udp_pkt.srcport, ip_pkt.dstip, udp_pkt.dstport)

                    return

        if action == "deny":
            # Inserta regla(s) de drop en el switch.
            def send_drop(src, dst):
                msg = of.ofp_flow_mod()
                msg.match.dl_src = src
                msg.match.dl_dst = dst
                msg.actions = []
                event.connection.send(msg)

            if deny_bidir:
                # Bloqueo en ambos sentidos (Regla 3)
                send_drop(eth.src, eth.dst)
                send_drop(eth.dst, eth.src)
                log.info("Bloqueo total entre %s ↔ %s", eth.src, eth.dst)
            else:
                # Bloqueo unidireccional (Reglas 1 y 2)
                send_drop(eth.src, eth.dst)
                log.info("Bloqueo unidireccional desde %s hacia %s", eth.src, eth.dst)
            return 

        dst_mac = eth.dst
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]

            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, event.port)
            fm.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(fm)
            log.debug("Forwarding %s → %s por puerto %s", eth.src, dst_mac, out_port)
        else:
            # aSi no conoazco la MAC destino
            po = of.ofp_packet_out(data=event.ofp, in_port=event.port)
            po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(po)

def launch():
    core.registerNew(Firewall)