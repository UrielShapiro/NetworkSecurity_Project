import humanfriendly
import scapy.all as scapy

from PacketAnalyzer import PacketAnalyzer


class FlowAnalyzer:
    def __init__(self):
        self.__flow_analysis = {}

    def __contains__(self, packet: scapy.Packet) -> bool:
        src_ip, dst_ip, src_port, dst_port, protocol = PacketAnalyzer.get_five_tuple(packet)
        return (src_ip, dst_ip, src_port, dst_port, protocol) in self.__flow_analysis.keys() or \
            (dst_ip, src_ip, dst_port, src_port, protocol) in self.__flow_analysis.keys()

    def update_packet(self, packet: scapy.Packet):
        print("Updating packet")
        src_ip, dst_ip, src_port, dst_port, protocol = PacketAnalyzer.get_five_tuple(packet)
        if (src_ip, dst_ip, src_port, dst_port, protocol) not in self.__flow_analysis.keys() and \
                (dst_ip, src_ip, dst_port, src_port, protocol) not in self.__flow_analysis.keys():
            raise Exception("Packet not found in flow analysis")
        if (src_ip, dst_ip, src_port, dst_port, protocol) in self.__flow_analysis.keys():
            self.__flow_analysis.get((src_ip, dst_ip, src_port, dst_port, protocol)).update_packet(packet)
        else:
            self.__flow_analysis.get((dst_ip, src_ip, dst_port, src_port, protocol)).update_packet(packet)

    def add_packet(self, packet: scapy.Packet):
        print("Adding packet")
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
            print(f"Flow: {index}:")
            index += 1
            flow.print()
            print("Amount of bytes transferred on this flow: " + str(flow.total_data) + " bytes")
            print("Amount of packets transferred on this flow: " + str(len(flow.packets)) + " packets")
            total_number_of_packets += len(flow.packets)
            total_number_of_bytes += flow.total_data
            print()  # Add a newline
        print("Flow analysis complete")
        print("Total size of packets: ", humanfriendly.format_size(total_number_of_bytes))
        print("Total number of packets: ", total_number_of_packets)
        print("Number of flows: ", len(self.__flow_analysis))
