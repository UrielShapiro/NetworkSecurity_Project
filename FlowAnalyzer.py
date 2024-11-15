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
        self.__flow_analysis = {}

    def __contains__(self, packet: scapy.Packet) -> bool:
        return PacketAnalyzer.get_five_tuple(packet) in self.__flow_analysis.keys()


    def update_packet(self, packet: scapy.Packet):
        print("Updating packet")
        if PacketAnalyzer.get_five_tuple(packet) not in self.__flow_analysis.keys():
            raise Exception("Packet not found in flow analysis")
        self.__flow_analysis.get(PacketAnalyzer.get_five_tuple(packet)).update_packet(packet)

    def add_packet(self, packet: scapy.Packet):
        print("Adding packet")
        self.__flow_analysis[PacketAnalyzer.get_five_tuple(packet)] = PacketAnalyzer(packet)

    def print(self):
        for flow in self.__flow_analysis.values():
            flow.print()
        print("Flow analysis complete")
        print("Number of flows: ", len(self.__flow_analysis))