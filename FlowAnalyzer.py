import scapy.all as scapy

from PacketAnalyzer import PacketAnalyzer


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
        total_number_of_packets = 0
        total_number_of_bytes = 0
        for flow in self.__flow_analysis.values():
            flow.print()
            print("Amount of bytes transferred on this flow: " + str(flow.total_data) + " bytes")
            print("Amount of packets transferred on this flow: " + str(len(flow.packets)) + " packets")
            if flow.abnormalities.__len__() > 0:
                print("Abnormalities:" + str(flow.abnormalities))
            total_number_of_packets += len(flow.packets)
            total_number_of_bytes += flow.total_data

        print("Flow analysis complete")
        print("Total number of bytes: ", total_number_of_bytes)
        print("Total number of packets: ", total_number_of_packets)
        print("Number of flows: ", len(self.__flow_analysis))