from typing import Any

import scapy.all as scapy
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
from PacketExceptions import TCPFlagsException, UDPPortException, MacAddressException

class PacketAnalyzer:
    def __init__(self, packet):

        self.packets = []
        self.packets.append(packet)
        self.abnormalities = {}
        self.total_data = len(packet)

        self.TCP = {
            "SYN": False,
            "SYN ACK": False,
            "ACK": False,
            "SYN Sender": str,
            "Syn-ACK Sender": str,
            "ACK Sender": str
        }
        self.UDP = {
            "DNS": False,
            "MDNS": False,
            "DHCP": False,
        }

        self.src_mac = None
        self.dst_mac = None

        if Ether in packet:
            self.src_mac = packet[Ether].src
            self.dst_mac = packet[Ether].dst
            # print(f"Source MAC: {self.src_mac}")
            # print(f"Destination MAC: {self.dst_mac}")

        self.src_ip = None
        self.dst_ip = None
        self.src_port = 0
        self.dst_port = 0
        self.protocol = None

        # Check if it's an IP packet (IPv4)
        if IP in packet:
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
            self.protocol = packet[IP].proto  # Protocol field from IP header

            # Handle TCP
            if packet.haslayer(TCP):
                self.src_port = packet[TCP].sport
                self.dst_port = packet[TCP].dport

            # Handle UDP
            elif packet.haslayer(UDP):
                self.src_port = packet[UDP].sport
                self.dst_port = packet[UDP].dport

            # Handle ICMP (no ports)
            elif packet.haslayer(ICMP):
                self.protocol = packet[IP].proto
                # ICMP does not use ports, so no src_port or dst_port

        # Check if it's an IPv6 packet
        elif IPv6 in packet:
            self.src_ip = packet[IPv6].src
            self.dst_ip = packet[IPv6].dst
            self.protocol = packet[IPv6].nh  # Next Header field for protocol

            # Handle TCP
            if packet.haslayer(TCP):
                self.src_port = packet[TCP].sport
                self.dst_port = packet[TCP].dport

            # Handle UDP
            elif packet.haslayer(UDP):
                self.src_port = packet[UDP].sport
                self.dst_port = packet[UDP].dport

            # Handle ICMPv6 (no ports)
            elif packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
                self.protocol = ICMPv6EchoRequest if packet.haslayer(ICMPv6EchoRequest) else ICMPv6EchoReply

            self.analyze_packet(packet)

    def update_packet(self, packet: scapy.Packet):
        self.packets.append(packet)
        self.total_data += len(packet)
        self.analyze_packet(packet)

    def analyze_packet(self, packet: scapy.Packet):
        # Check if it's an IP packet (IPv4)
        if Ether in packet:
            self.process_mac(packet)

        if IP in packet:
            # Handle TCP
            if packet.haslayer(TCP):
                self.process_tcp(packet)
            elif packet.haslayer(UDP):
                self.process_udp(packet)


    def process_tcp(self, packet):

        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

        all_flags = FIN | SYN | ACK | PSH | RST | URG | ECE | CWR
        packet_flags = packet[TCP].flags
        # Check anomalies first:
        try:
            # Check if all flags are set
            if (packet_flags & all_flags) == all_flags:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("All flags are set together")

            # Check for SYN, ACK, FIN flags raised together
            if packet_flags & SYN and packet_flags & ACK and packet_flags & FIN:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("SYN, ACK and FIN flags are set together")

            # Check for SYN and FIN flags together
            if packet_flags & SYN and packet_flags & ACK:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("SYN and FIN flags are set together")

            # Check for SYN and RST flags together
            if packet_flags & SYN and packet_flags & RST:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("SYN and RST flags are set together")

            # Check for FIN and RST flags together
            if packet_flags & FIN and packet_flags & RST:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("FIN and RST flags are set together")

            # Check if Only FIN flag is set alone
            if packet_flags & FIN and packet_flags & ~FIN == 0:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("Only FIN flag is set")

            # Check for PSH flag raised alone
            if packet_flags & PSH and packet_flags & ~PSH == 0:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("Only PSH flag is set")

            # Check for URG flag raised alone
            if packet_flags & URG and packet_flags & ~URG == 0:
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("Only URG flag is set")
        except TCPFlagsException as e:
            print("TCP Flags Abnormality " + e.message)
            self.add_abnormality("TCP Flags Abnormality " + e.message)

        # Check for RST flags
        if packet_flags & RST or (packet_flags & FIN and packet_flags & ACK):
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False

        # Check for SYN flag (Initial SYN)
        if packet[TCP].flags & SYN and not packet[TCP].flags & ACK:
            self.TCP["SYN"] = True
            self.TCP["SYN Sender"] = PacketAnalyzer.get_sender_ip(packet)
        # Check for SYN ACK flag (Initial SYN-ACK)
        elif packet[TCP].flags & SYN and packet[TCP].flags & ACK and not self.TCP["SYN ACK"] and self.TCP["SYN Sender"] is not None and self.TCP["SYN Sender"] != PacketAnalyzer.get_sender_ip(packet):
            self.TCP["SYN ACK"] = True
            self.TCP["Syn-ACK Sender"] = PacketAnalyzer.get_sender_ip(packet)
        # Check for ACK flag (Not only initial ACK)
        elif packet[TCP].flags & ACK and self.TCP["SYN"] and self.TCP["SYN ACK"]:
            self.TCP["ACK"] = True
            self.TCP["ACK Sender"] = PacketAnalyzer.get_sender_ip(packet)

        if self.TCP["SYN"] and self.TCP["SYN ACK"] and self.TCP["ACK"]:
            if self.TCP["SYN Sender"] != self.TCP["ACK Sender"]:
                self.add_abnormality("TCP Three-Way Handshake Abnormality - SYN sender and ACK sender are not the same")
            if self.TCP["Syn-ACK Sender"] == self.TCP["SYN Sender"]:
                self.add_abnormality("TCP Three-Way Handshake Abnormality - SYN-ACK sender is the same as SYN sender")
            if self.TCP["Syn-ACK Sender"] == self.TCP["ACK Sender"]:
                self.add_abnormality("TCP Three-Way Handshake Abnormality - SYN-ACK sender is the same as ACK sender")

    def process_udp(self, packet):
        # Check for DNS

        if DNS in packet:
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                self.UDP["DNS"] = True
            elif (packet[UDP].sport == 5353 or packet[UDP].dport == 5353) and packet[IP].dst == "224.0.0.251":
                self.UDP["MDNS"] = True
            else:
                raise UDPPortException("DNS packet is not on the standard port 53")
        # Check for DHCP
        elif DHCP in packet:
            if (packet[UDP].sport == 67 and packet[UDP].dport == 68) or (packet[UDP].sport == 68 and packet[UDP].dport == 67):
                self.UDP["DHCP"] = True
            else:
                raise UDPPortException("DHCP packet is not on the standard port 67")
        else:
            pass

    def process_mac(self, packet: scapy.Packet):
        try:
            if (self.src_mac != packet[Ether].src and self.src_mac != packet[Ether].dst) \
                    or (self.dst_mac != packet[Ether].src and self.dst_mac != packet[Ether].dst):
                raise MacAddressException("MAC address mismatch")
        except MacAddressException as e:
            self.add_abnormality("MAC Address Abnormality " + e.message)


    def add_abnormality(self, anomaly: str):
        if anomaly not in self.abnormalities:
            self.abnormalities[anomaly] = 1
        else:
            self.abnormalities[anomaly] += 1

    def dst_(self):
        return self.dst_ip, self.dst_port

    def src_(self):
        return self.src_ip, self.src_port

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, PacketAnalyzer):
            return False
        return (
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol) ==
            (other.src_ip, other.src_port, other.dst_ip, other.dst_port, other.protocol)
            or
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol) ==
            (other.dst_ip, other.dst_port, other.src_ip, other.src_port, other.protocol)
        )
    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return f"Packet: {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} Protocol: {self.protocol}"

    def print(self):
        for packet in self.packets.copy():  # Copy to avoid modifying the list while iterating
            print(packet.summary())


    @staticmethod
    def get_five_tuple(packet: scapy.Packet) -> tuple:
        src_ip, dst_ip, src_port, dst_port, protocol = None, None, None, None, None
        if IP in packet:
            print("Added IP Packet")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
        elif IPv6 in packet:
            print("Added IPv6 Packet")
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = packet[IP].proto
        elif ARP in packet:
            protocol = packet[Ether].type
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_port = 0
            dst_port = 0

        if src_ip is not None and dst_ip is not None and protocol is not None:
            return src_ip, dst_ip, src_port, dst_port, protocol
        else:
            packet.show()
            raise ValueError("Packet does not contain necessary information")

    @staticmethod
    def get_sender_ip(packet: scapy.Packet) -> Any | None:
        if IP in packet:
            return packet[IP].src
        elif IPv6 in packet:
            return packet[IPv6].src
        else:
            return None