from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.info("Firewall iniciado (modo básico)")

    def _handle_ConnectionUp(self, event):
        log.info("Conexión establecida con switch %s", event.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port
        dpid = event.dpid

        try:
            ip_packet = packet.find('ipv4')
            transport = ip_packet.find('tcp') or ip_packet.find('udp')
        except:
            ip_packet = None
            transport = None

        log.debug("PacketIn recibido en switch %s (puerto %s)", dpid, in_port)

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = in_port
        event.connection.send(msg)

def launch():
    core.registerNew(Firewall)