from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
from scapy.layers.ssh import SSH

import FlowAbnormality
from FlowAbnormality import *
from PacketExceptions import TCPFlagsException, MacAddressException


class PacketAnalyzer:
    def __init__(self, packet: scapy.Packet):
        self.packets = []
        self.packets.append(packet)
        self.abnormalities = {}
        self.total_data = len(packet)
        self.__resolvedIPs = []
        self.__requestedDomains = []

        self.TCP = {
            "SYN": False,
            "SYN ACK": False,
            "ACK": False,
            "SYN Sender": str,
            "Syn-ACK Sender": str,
            "ACK Sender": str
        }
        self.UDP = {
            "DNS": {
                "Query": None,  # Will store the IP address of the DNS query
                "Response": None,  # Will store the IP address of the DNS response
                "ID": []  # Will store the ID of the DNS queries
            },
            "MDNS": False,
            "DHCP": {
                "ID": []
            },
        }

        self.SSH = {
            "failed_attempts": defaultdict(list)  # Dictionary to store failed login attempts as a list of timestamps
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
                # RST flag is set, so we reset the SYN, SYN ACK and ACK flags
                self.TCP["SYN"] = False
                self.TCP["SYN ACK"] = False
                self.TCP["ACK"] = False
                raise TCPFlagsException("All flags are set together")

            # Check for SYN, ACK, FIN flags raised together
            if packet_flags & SYN and packet_flags & ACK and packet_flags & FIN:
                raise TCPFlagsException("SYN, ACK and FIN flags are set together")

            # Check for SYN and FIN flags together
            if packet_flags & SYN and packet_flags & FIN:
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
                raise TCPFlagsException("Only FIN flag is set")

            # Check for PSH flag raised alone
            if packet_flags & PSH and packet_flags & ~PSH == 0:
                raise TCPFlagsException("Only PSH flag is set")

            # Check for URG flag raised alone
            if packet_flags & URG and packet_flags & ~URG == 0:
                raise TCPFlagsException("Only URG flag is set")

        except TCPFlagsException as e:
            print("TCP Flags Abnormality " + e.message)
            anomaly = FlowAbnormality(abnormality_type="TCP Flags Abnormality",
                                      description=e.message,
                                      level=AbnormalityType.FLAGS_VIOLATION)
            self.add_abnormality(anomaly)

        # Check for RST flag or FIN and ACK flags together to reset the handshake
        if packet_flags & RST or (packet_flags & FIN and packet_flags & ACK):
            self.TCP["SYN"] = False
            self.TCP["SYN ACK"] = False
            self.TCP["ACK"] = False

        # Check for SYN flag (Initial SYN)
        if packet_flags & SYN and not packet_flags & ACK and not self.TCP["SYN"]:
            # SYN flag is set and ACK flag is not set and SYN flag was not set before
            self.TCP["SYN"] = True
            self.TCP["SYN Sender"] = PacketAnalyzer.get_sender_ip(packet)

        # Check for SYN ACK flag (Initial SYN-ACK)
        elif packet_flags & SYN and packet_flags & ACK and not self.TCP["SYN ACK"] and self.TCP["SYN"]:
            self.TCP["SYN ACK"] = True
            self.TCP["Syn-ACK Sender"] = PacketAnalyzer.get_sender_ip(packet)
        # Check for ACK flag (Not only initial ACK)
        elif packet_flags & ACK and self.TCP["SYN"] and self.TCP["SYN ACK"]:
            self.TCP["ACK"] = True
            self.TCP["ACK Sender"] = PacketAnalyzer.get_sender_ip(packet)

        if self.TCP["SYN"] and self.TCP["SYN ACK"] and self.TCP["ACK"]:
            if self.TCP["SYN Sender"] != self.TCP["ACK Sender"]:
                anomaly = FlowAbnormality(abnormality_type="TCP Three-Way Handshake Abnormality",
                                          description="SYN sender and ACK sender are not the same",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if self.TCP["Syn-ACK Sender"] == self.TCP["SYN Sender"]:
                anomaly = FlowAbnormality(abnormality_type="TCP Three-Way Handshake Abnormality",
                                          description="SYN-ACK sender is the same as SYN sender",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if self.TCP["Syn-ACK Sender"] == self.TCP["ACK Sender"]:
                anomaly = FlowAbnormality(abnormality_type="TCP Three-Way Handshake Abnormality",
                                          description="SYN-ACK sender is the same as ACK sender",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)

        # Check for protocols that use TCP:
        if SSH in packet:
            self.process_ssh(packet)

    def process_ssh(self, packet: scapy.Packet):
        # TODO: Test functionality
        RST = 0x04
        PSH = 0x08
        ACK = 0x10

        TIME_WINDOW = timedelta(seconds=60)
        FAILED_ATTEMPTS_THRESHOLD = 10

        tcp_layer = packet[TCP]
        if tcp_layer.sport != 22 and tcp_layer.dport != 22:
            anomaly = FlowAbnormality(abnormality_type="SSH Abnormality",
                                      description="SSH packet is not on standard port 22",
                                      level=AbnormalityType.PORT_VIOLATION)
            self.add_abnormality(anomaly)

        # Analyze failed login attempts (TCP RST for example)
        src_ip = tcp_layer.src
        if tcp_layer.flags & RST:  # TCP RST could indicate failed attempt
            self.SSH["failed_attempts"][src_ip].append(datetime.now())
            # Check if there was an attempted brute force attack

            # Remove old attempts outside the time window
            now = datetime.now()
            self.SSH["failed_attempts"][src_ip] = [t for t in self.SSH["failed_attempts"][src_ip] if
                                                   now - t < TIME_WINDOW]
            # Check if failed attempts, exceed the threshold
            if len(self.SSH["failed_attempts"][src_ip]) > FAILED_ATTEMPTS_THRESHOLD:
                anomaly = FlowAbnormality(abnormality_type="SSH Abnormality",
                                          description="Brute force attack detected",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)
                del self.SSH["failed_attempts"][src_ip]  # Reset after reporting

        if tcp_layer.flags & (PSH | ACK):  # Payload transfer
            payload_size = len(packet[TCP].payload)
            if payload_size > 1000:  # Arbitrary large payload size
                anomaly = FlowAbnormality(abnormality_type="SSH Abnormality",
                                          description="Large SSH payload size",
                                          level=AbnormalityType.PAYLOAD_VIOLATION)
                self.add_abnormality(anomaly)

    def process_udp(self, packet):
        # Check for DNS
        if DNS in packet:
            if packet[UDP].sport == 5353 or packet[UDP].dport == 5353:
                self.UDP["MDNS"] = True

            self.process_dns(packet)

        # Check for DHCP
        elif DHCP in packet:
            self.process_dhcp(packet)

    def process_dns(self, packet: scapy.Packet):
        dns = packet[DNS]  # Take the DNS layer of the packet

        self.process_dns_header(packet)

        if dns.qr == 0:  # Query packet
            self.UDP["DNS"]["Query"] = PacketAnalyzer.get_sender_ip(packet)
            domain_name = dns.qd.qname.decode("utf-8")
            domain_suffix = domain_name.split(".")
            if len(domain_suffix) >= 2:
                domain_name = '.'.join(domain_suffix[-2:])  # Get the last two parts of the domain name
            if domain_name not in self.__requestedDomains:  # Check if the domain name has been requested before (DNS Tunneling)
                self.__requestedDomains.append(domain_name)
            else:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS Tunneling suspected for domain: " + domain_name,
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if dns.id in self.UDP["DNS"]["ID"]:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS packet ID is reused",
                                          level=AbnormalityType.TRANSACTION_VIOLATION)
                self.add_abnormality(anomaly)
            else:
                self.UDP["DNS"]["ID"].append(dns.id)

        elif dns.qr == 1:  # Response packet
            if not self.UDP["DNS"]["Query"]:  # Check if there was a query before the response
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS response without a query",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)
            self.UDP["DNS"]["Response"] = PacketAnalyzer.get_sender_ip(packet)
            self.__resolvedIPs.append(dns.an.rdata)  # Add the resolved IP to the list of resolved IPs

            # Check for a query response mismatch
            if dns.id not in self.UDP["DNS"]["ID"]:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS ID does not match any query",
                                          level=AbnormalityType.TRANSACTION_VIOLATION)
                self.add_abnormality(anomaly)

            if self.UDP["MDNS"]:
                if dns.aa != 1:
                    anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                              description="MDNS packet is not authoritative",
                                              level=AbnormalityType.FLAGS_VIOLATION)
                    self.add_abnormality(anomaly)

        if self.UDP["MDNS"]:
            ip = packet[IP].dst
            if ip != "224.0.0.251" and ip != "FF02::FB":  # Check if the MDNS packet is not on the standard multicast address
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="MDNS packet is not on the standard multicast address",
                                          level=AbnormalityType.HEADER_VIOLATION)
                self.add_abnormality(anomaly)

        elif not (packet[UDP].sport == 53 or packet[UDP].dport == 53):
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="DNS packet is not on the standard port 53",
                                      level=AbnormalityType.PORT_VIOLATION)
            self.add_abnormality(anomaly)

        if packet[DNS].opcode != 0:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="DNS packet is not a standard query",
                                      level=AbnormalityType.INFO)
            self.add_abnormality(anomaly)

            # Check for suspiciously high number of queries or answers
            if dns.qdcount > 10:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="Suspicious number of questions",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if dns.ancount > 20:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="Suspicious number of answers",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if dns.nscount > 10:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="Suspicious number of authority records",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            if dns.arcount > 10:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="Suspicious number of additional records",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)

                # Check for DNS packet size abnormalities
                if len(packet) > 512:
                    anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                              description="Packet size exceeds standard UDP DNS packet size (512 bytes)",
                                              level=AbnormalityType.PAYLOAD_VIOLATION)
                    self.add_abnormality(anomaly)

    def process_dns_header(self, packet: scapy.Packet):
        dns = packet[DNS]
        # Check for abnormal header flags
        if not dns.qr in [0, 1]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS QR flag",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)
        if dns.opcode not in [0, 1, 2, 4, 5]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Unsupported DNS Opcode",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)
        if dns.rcode not in range(0, 16):  # RCODE is a 4-bit field (0-15)
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS RCODE",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)

        # Check for abnormal flags
        if dns.aa not in [0, 1]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS AA flag",
                                      level=AbnormalityType.FLAGS_VIOLATION)
            self.add_abnormality(anomaly)
        if dns.tc not in [0, 1]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS Truncation flag",
                                      level=AbnormalityType.FLAGS_VIOLATION)
            self.add_abnormality(anomaly)
        if dns.rd not in [0, 1]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS Recursion Desired flag",
                                      level=AbnormalityType.FLAGS_VIOLATION)
            self.add_abnormality(anomaly)
        if dns.ra not in [0, 1]:
            anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                      description="Invalid DNS Recursion Available flag",
                                      level=AbnormalityType.FLAGS_VIOLATION)
            self.add_abnormality(anomaly)

    def process_dhcp(self, packet: scapy.Packet):
        """
        Function to analyze a DHCP packet using Scapy.
        Assumes that `packet` is a Scapy packet.
        """

        bootp = packet[BOOTP]
        dhcp = packet[DHCP]

        # Check for correct ports
        if not (packet[UDP].sport == 67 or packet[UDP].sport == 68 or packet[UDP].dport == 67 or packet[
            UDP].dport == 68):
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description="DHCP packet is not on standard ports 67 or 68",
                                      level=AbnormalityType.PORT_VIOLATION)
            self.add_abnormality(anomaly)

        # Check for message type abnormality
        message_type = None
        for option in dhcp.options:
            if option[0] == 'message-type':
                message_type = option[1]
                break  # Break out of the loop if message type is found
        if message_type is None:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description="No DHCP message type found in packet",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)
        else:
            if message_type not in [1, 2, 3, 4, 5, 6, 7, 8]:
                anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                          description=f"Unknown DHCP message type: {message_type}",
                                          level=AbnormalityType.HEADER_VIOLATION)
                self.add_abnormality(anomaly)

        # Check for Transaction ID reuse
        if bootp.xid in self.UDP["DHCP"]["TransactionID"]:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description="Transaction ID is reused",
                                      level=AbnormalityType.TRANSACTION_VIOLATION)
            self.add_abnormality(anomaly)
        else:
            self.UDP["DHCP"]["TransactionID"].append(bootp.xid)

        # Check for invalid hardware address length
        if bootp.hlen != 6:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description=f"Invalid hardware address length",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)

        # Check for broadcast flag correctness
        if bootp.flags not in [0x0000, 0x8000]:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description=f"Invalid broadcast flag value {bootp.flags}",
                                      level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)

        # Check for suspicious number of options
        if len(dhcp.options) > 20:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description="Suspicious number of DHCP options",
                                      level=AbnormalityType.WARNING)
            self.add_abnormality(anomaly)

        # Check for server identifier in Offer or Ack
        if message_type in [2, 5]:  # DHCPOFFER or DHCPACK
            server_id_found = any(option[0] == 'server_id' for option in dhcp.options)
            if not server_id_found:
                anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                          description="No server identifier found in DHCPOFFER or DHCPACK",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)

        # Check for requested IP in Request
        if message_type == 3:  # DHCPREQUEST
            requested_ip_found = any(option[0] == 'requested_addr' for option in dhcp.options)
            if not requested_ip_found:
                anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                          description="No requested IP address found in DHCPREQUEST",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)

    def process_mac(self, packet: scapy.Packet):
        try:
            if (self.src_mac != packet[Ether].src and self.src_mac != packet[Ether].dst) \
                    or (self.dst_mac != packet[Ether].src and self.dst_mac != packet[Ether].dst):
                raise MacAddressException("MAC address mismatch")
        except MacAddressException as e:
            anomaly = FlowAbnormality(abnormality_type="MAC Address Abnormality",
                                      description=e.message,
                                      level=AbnormalityType.ALERT)
            self.add_abnormality(anomaly)

    def add_abnormality(self, anomaly: FlowAbnormality):
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
        for key, value in self.abnormalities.items():
            print(f"Abnormality: {key} - Occurrences: {value}")
        # for packet in self.packets.copy():  # Copy to avoid modifying the list while iterating
        #     print(packet.summary())

    def get_abnormalities(self):
        for abnormality in self.abnormalities.keys():
            yield abnormality

    @staticmethod
    def get_five_tuple(packet: scapy.Packet) -> tuple:
        src_ip, dst_ip, src_port, dst_port, protocol = None, None, None, None, None
        if IP in packet:
            # print("Added IP Packet")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
        elif IPv6 in packet:
            # print("Added IPv6 Packet")
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
            raise ValueError("Packet does not contain IP information")
