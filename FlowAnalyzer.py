import humanfriendly
import scapy.all as scapy

import logging_setup
from PacketAnalyzer import PacketAnalyzer


class FlowAnalyzer:
    def __init__(self):
        self.logger = logging_setup.get_logger(self.__class__.__name__)
        self.__flow_analysis = {}

    def __contains__(self, packet: scapy.Packet) -> bool:
        src_ip, dst_ip, src_port, dst_port, protocol = PacketAnalyzer.get_five_tuple(packet)
        return (src_ip, dst_ip, src_port, dst_port, protocol) in self.__flow_analysis.keys() or \
            (dst_ip, src_ip, dst_port, src_port, protocol) in self.__flow_analysis.keys()

    def update_packet(self, packet: scapy.Packet):
        self.logger.debug(f"Updating flow with packet: {packet.summary()}")
        src_ip, dst_ip, src_port, dst_port, protocol = PacketAnalyzer.get_five_tuple(packet)
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if flow_key in self.__flow_analysis:
            self.__flow_analysis[flow_key].update_packet(packet)
        elif reverse_flow_key in self.__flow_analysis:
            self.__flow_analysis[reverse_flow_key].update_packet(packet)
        else:
            self.logger.error("Attempted to update a non-existent flow.")
            return

    def add_packet(self, packet: scapy.Packet):
        self.logger.info("Adding packet: " + packet.summary())
        self.__flow_analysis[PacketAnalyzer.get_five_tuple(packet)] = PacketAnalyzer(packet)

    def get_abnormalities(self):
        for five_tuple in self.__flow_analysis.keys():
            packet_analyzer = self.__flow_analysis.get(five_tuple)
            for abnormality in packet_analyzer.get_abnormalities():
                yield five_tuple, abnormality

    def print(self):
        total_number_of_packets = 0
        total_number_of_bytes = 0
        index = 1
        for flow in self.__flow_analysis.values():
            abnormalities = flow.get_abnormalities()
            if len(list(abnormalities)) > 0:
                print(f"Flow: {index}:")
                flow.print()
                print("Amount of bytes transferred on this flow: " + str(flow.total_data) + " bytes")
                print("Amount of packets transferred on this flow: " + str(flow.num_of_packets) + " packets")
                print()  # Add a newline
            index += 1
            total_number_of_packets += flow.num_of_packets
            total_number_of_bytes += flow.total_data
        print("Flow analysis complete")
        print("Total size of packets: ", humanfriendly.format_size(total_number_of_bytes))
        print("Total number of packets: ", total_number_of_packets)
        print("Number of flows: ", len(self.__flow_analysis))
