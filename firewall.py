from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
import json
import os

log = core.getLogger()

# Constants
IPV4_TYPE = 0x0800
TCP_PROTO_NUMBER = 6
UDP_PROTO_NUMBER = 17
ICMP_PROTO_NUMBER = 1

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.rules = self.load_rules()
        log.debug("Enabling Firewall Module")

    def load_rules(self):
        """Load firewall rules from JSON file."""
        try:
            # Try to find rules.json in current directory or parent directories
            current_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(current_dir, 'rules.json')
            
            if not os.path.exists(rules_path):
                # Try parent directory
                rules_path = os.path.join(os.path.dirname(current_dir), 'rules.json')
            
            if not os.path.exists(rules_path):
                # Try project root
                rules_path = os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'rules.json')
            
            with open(rules_path, 'r') as f:
                rules = json.load(f)
                log.info("Firewall rules loaded from: %s", rules_path)
                log.debug("Rules: %s", rules)
                return rules
        except Exception as e:
            log.error("Error loading rules.json: %s", e)
            log.info("Using default hardcoded rules")
            return self.get_default_rules()

    def get_default_rules(self):
        """Return default firewall rules if JSON file is not found."""
        return [
            {
                "description": "Block all traffic to port 80",
                "dst_port": 80,
                "protocol": "any",
                "action": "deny"
            },
            {
                "description": "Block UDP traffic from h1 to port 5001",
                "src_ip": "10.0.0.1",
                "dst_port": 5001,
                "protocol": "UDP",
                "action": "deny"
            },
            {
                "description": "Block all communication between h1 and h3",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.3",
                "protocol": "any",
                "action": "deny"
            },
            {
                "description": "Block all communication between h3 and h1",
                "src_ip": "10.0.0.3",
                "dst_ip": "10.0.0.1",
                "protocol": "any",
                "action": "deny"
            }
        ]

    def _handle_ConnectionUp(self, event):
        """Handle switch connection event."""
        log.debug("Switch %s has been connected", dpidToStr(event.dpid))
        
        # Install firewall rules as flow entries
        self.install_firewall_rules(event.connection)
        
        # Install a low-priority rule to handle other traffic (L2 learning)
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)
        
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

    def install_firewall_rules(self, connection):
        """Install firewall rules as OpenFlow flow entries."""
        for rule in self.rules:
            if rule.get("action") == "deny":
                # Create flow mod message to drop packets
                msg = of.ofp_flow_mod()
                msg.priority = 100  # High priority for firewall rules
                
                # Build match criteria
                match = of.ofp_match()
                match.dl_type = IPV4_TYPE
                
                # Source IP
                if "src_ip" in rule:
                    match.nw_src = IPAddr(rule["src_ip"])
                
                # Destination IP
                if "dst_ip" in rule:
                    match.nw_dst = IPAddr(rule["dst_ip"])
                
                # Protocol and port
                protocol = rule.get("protocol", "any").upper()
                if protocol == "TCP" or (protocol == "ANY" and "dst_port" in rule):
                    # For port 80 rule, we need both TCP and UDP
                    if rule.get("dst_port") == 80:
                        # Install TCP rule
                        tcp_msg = of.ofp_flow_mod()
                        tcp_msg.priority = 100
                        tcp_match = of.ofp_match()
                        tcp_match.dl_type = IPV4_TYPE
                        tcp_match.nw_proto = TCP_PROTO_NUMBER
                        tcp_match.tp_dst = 80
                        tcp_msg.match = tcp_match
                        # No actions = drop
                        connection.send(tcp_msg)
                        
                        # Install UDP rule
                        udp_msg = of.ofp_flow_mod()
                        udp_msg.priority = 100
                        udp_match = of.ofp_match()
                        udp_match.dl_type = IPV4_TYPE
                        udp_match.nw_proto = UDP_PROTO_NUMBER
                        udp_match.tp_dst = 80
                        udp_msg.match = udp_match
                        # No actions = drop
                        connection.send(udp_msg)
                        continue
                    else:
                        match.nw_proto = TCP_PROTO_NUMBER
                        if "dst_port" in rule:
                            match.tp_dst = rule["dst_port"]
                
                elif protocol == "UDP":
                    match.nw_proto = UDP_PROTO_NUMBER
                    if "dst_port" in rule:
                        match.tp_dst = rule["dst_port"]
                
                elif protocol == "ICMP":
                    match.nw_proto = ICMP_PROTO_NUMBER
                
                # For "any" protocol without specific port, install separate rules
                elif protocol == "ANY" and "dst_port" not in rule:
                    # Install rules for TCP, UDP, and ICMP
                    for proto_num in [TCP_PROTO_NUMBER, UDP_PROTO_NUMBER, ICMP_PROTO_NUMBER]:
                        proto_msg = of.ofp_flow_mod()
                        proto_msg.priority = 100
                        proto_match = of.ofp_match()
                        proto_match.dl_type = IPV4_TYPE
                        proto_match.nw_proto = proto_num
                        
                        if "src_ip" in rule:
                            proto_match.nw_src = IPAddr(rule["src_ip"])
                        if "dst_ip" in rule:
                            proto_match.nw_dst = IPAddr(rule["dst_ip"])
                        
                        proto_msg.match = proto_match
                        # No actions = drop
                        connection.send(proto_msg)
                    continue
                
                msg.match = match
                # No actions specified = drop the packet
                connection.send(msg)
                
                log.info("Installed firewall rule: %s", rule.get("description", "No description"))

    def _handle_PacketIn(self, event):
        """Handle PacketIn events for L2 learning."""
        packet = event.parsed
        
        # Simple L2 learning switch behavior for allowed traffic
        if packet.type == 0x0806:  # ARP
            # Flood ARP packets
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = event.port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
        else:
            # For other packets, flood for simplicity
            # In a real implementation, you'd implement MAC learning
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = event.port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

def launch():
    """Starting the Firewall module."""
    core.registerNew(Firewall)