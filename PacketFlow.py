import scapy.all as scapy
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from PacketExceptions import TCPFlagsException, UDPPortException, MacAddressException

class PacketFlow:
    def __init__(self, packet):
        self.TCP = {
            "SYN": False,
            "SYN ACK": False,
            "ACK": False,
        }
        self.UDP = {
            "DNS": False,
            "DHCP": False,
        }
        self.src_mac = None
        self.dst_mac = None

        if packet.haslayer(Ether):
            self.src_mac = packet[Ether].src
            self.dst_mac = packet[Ether].dst

        self.analyze_packet(packet)

    def analyze_packet(self, packet: scapy.Packet):
        # Check if it's an IP packet (IPv4)
        if packet.haslayer(Ether):
            self.process_mac(packet)

        if IP in packet:
            protocol = packet[IP].proto
            # Handle TCP
            if packet.haslayer(TCP):
                self.process_tcp(packet)
            elif packet.haslayer(UDP):
                self.process_udp(packet)



    def process_tcp(self, packet):
        all_flags = TCP.flags.F | TCP.flags.S | TCP.flags.A | TCP.flags.P | TCP.flags.R | TCP.flags.U | TCP.flags.E | TCP.flags.C
        packet_flags = packet[TCP].flags
        # Check anomalies first:

        # Check if all flags are set
        if packet_flags & all_flags == all_flags:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("All flags are set together")

        # Check for SYN, ACK, FIN flags raised together
        if packet_flags & TCP.flags.S and packet_flags & TCP.flags.A and packet_flags & TCP.flags.F:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("SYN, ACK and FIN flags are set together")

        # Check for SYN and FIN flags together
        if packet_flags & TCP.flags.S and packet_flags & TCP.flags.F:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("SYN and FIN flags are set together")

        # Check for SYN and RST flags together
        if packet_flags & TCP.flags.S and packet_flags & TCP.flags.R:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("SYN and RST flags are set together")

        # Check for FIN and RST flags together
        if packet_flags & TCP.flags.F and packet_flags & TCP.flags.R:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("FIN and RST flags are set together")

        # Check if Only FIN flag is set alone
        if packet_flags & TCP.flags.F and packet_flags & ~TCP.flags.F == 0:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("Only FIN flag is set")

        # Check for PSH flag raised alone
        if packet_flags & TCP.flags.P and packet_flags & ~TCP.flags.P == 0:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("Only PSH flag is set")

        # Check for URG flag raised alone
        if packet_flags & TCP.flags.U and packet_flags & ~TCP.flags.U == 0:
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False
            raise TCPFlagsException("Only URG flag is set")

        # Check for RST flags
        if packet_flags & TCP.flags.R or (packet_flags & TCP.flags.F and packet_flags & TCP.flags.A):
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False

        # Check for SYN flag (Initial SYN)
        if (packet[TCP].flags & TCP.flags.S and not packet[TCP].flags & TCP.flags.A and not self.TCP["SYN ACK"]
                and not self.TCP["SYN"] and not self.TCP["ACK"]):
            self.TCP["SYN"] = True
        # Check for SYN ACK flag (Initial SYN-ACK)
        elif packet[TCP].flags & TCP.flags.S and packet[TCP].flags & TCP.flags.A and not self.TCP["SYN ACK"]:
            self.TCP["SYN ACK"] = True
        # Check for ACK flag (Not only initial ACK)
        elif packet[TCP].flags & TCP.flags.A and self.TCP["SYN"] and self.TCP["SYN ACK"]:
            self.TCP["ACK"] = True
        else:
            raise TCPFlagsException("Invalid flag combination")

    def process_udp(self, packet):
        # Check for DNS
        if packet.haslayer(DNS):
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                self.UDP["DNS"] = True
            else:
                raise UDPPortException("DNS packet is not on the standard port 53")
        # Check for DHCP
        elif packet.haslayer(DHCP):
            if (packet[UDP].sport == 67 and packet[UDP].dport == 68) or (packet[UDP].sport == 68 and packet[UDP].dport == 67):
                self.UDP["DHCP"] = True
            else:
                raise UDPPortException("DHCP packet is not on the standard port 67")
        else:
            pass

    def update_packet(self, packet):
        self.analyze_packet(packet)

    def process_mac(self, packet):
        if (self.src_mac != packet[Ether].src and self.src_mac != packet[Ether].dst) \
                or (self.dst_mac != packet[Ether].src and self.dst_mac != packet[Ether].dst):
            raise MacAddressException("MAC address was spoofed")


