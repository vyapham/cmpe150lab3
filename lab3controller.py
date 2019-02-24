# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    # print "Example Code."

    msg = of.ofp_flow_mod()
    #msg.match = of.ofp_match.from_packet(packet)
    msg.data = packet_in

    """def flood():
      msg = of.ofp_packet_out()
      #msg = of.ofp_flow_mod()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = packet_in
      msg.in_port = event.port
      self.connection.send(msg)
    """
    def drop(duration = None):
      if duration is None:
        msg = of.ofp_packet_out()
        msg.buffer = packet_in.buffer_id
        msg.in_port = OFPP_NONE
        self.connection.send(msg)

    if packet.type == pkt.ethernet.ARP_TYPE:
      print "ARP"
      msg.match.dl_type = pkt.ethernet.ARP_TYPE
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      self.connection.send(msg)
    elif (packet.type == pkt.ethernet.IP_TYPE) and (packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL):
      print "IP-ICMP"
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      self.connection.send(msg)
    elif (packet.type == pkt.ethernet.IP_TYPE) and (packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL):
      print "IP-TCP"
      #msg.match.dl_type = packet.type
      #msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
      
      ip_packet = packet.payload
      src_ip = ip_packet.srcip
      dst_ip = ip_packet.dstip
      #src_ip = packet.src
      #dst_ip = packet.dst

      if (src_ip == '10.0.1.10') and (dst_ip == '10.0.1.30'):
        print "tcp h1 -> h3"
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.match.dl_type = packet.type
        msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)
      elif (src_ip == '10.0.1.30') and (dst_ip == '10.0.1.10'):
        print "tcp h3 -> h1"
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.match.dl_type = packet.type
        msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)
      else:
        print "tcp else"
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.match.dl_type = packet.type
        msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        self.connection.send(msg)
        
    else:
      print "else"
      msg.actions.append(of.ofp_action_out(port = of.OFPP_NONE))
      self.connection.send(msg)
      
    return

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
