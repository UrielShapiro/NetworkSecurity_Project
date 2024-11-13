from typing import List, Dict

import scapy.all as scapy
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from PacketAnalyzer import PacketAnalyzer
from PacketExceptions import TCPFlagsException, UDPPortException, MacAddressException


class FlowAnalyzer:
    def __init__(self):
        self.__flow_analysis = Dict[PacketAnalyzer, List[str, list()]]

    def update_packet(self, packet: scapy.Packet):
        PacketAnalyzer.analyze_packet(packet)
