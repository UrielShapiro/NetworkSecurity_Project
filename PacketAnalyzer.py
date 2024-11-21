from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import scapy.all as scapy
import tldextract
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6Unknown, ICMPv6ND_Redirect, ICMPv6ND_NS, \
    ICMPv6TimeExceeded
from scapy.layers.l2 import Ether, ARP
from scapy.layers.ssh import SSH
from scapy.packet import Raw

import FlowAbnormality
import logging_setup
from FlowAbnormality import *
from PacketExceptions import TCPFlagsException


class PacketAnalyzer:
    """"
    This class is used to analyze packets and detect abnormalities in the network traffic.
    It uses Scapy to parse the packets and extract the necessary information.
    """

    def __init__(self, packet: scapy.Packet):
        self.logger = logging_setup.get_logger(self.__class__.__name__)
        self.num_of_packets = 1
        self.abnormalities = {}
        self.total_data = len(packet)
        self.__resolvedIPs = []
        self.__requestedDomains = []
        self.__arp_table = {}

        self.TCP = {
            "SYN": False,
            "SYN ACK": False,
            "ACK": False,
            "SYN Sender": str,
            "Syn-ACK Sender": str,
            "ACK Sender": str,
            "SYN Packets": defaultdict(list),  # Dictionary to store SYN packets as a list of timestamps
            "RST Packets": defaultdict(list),  # Dictionary to store RST packets as a list of timestamps
            "FTP": defaultdict(list),  # Dictionary to store FTP packets as a list of timestamps
            "SMB Authentication": defaultdict(list), # Dictionary to store SMB authentication packets as a list of timestamps
            "IMAP Authentication": defaultdict(list),  # Dictionary to store IMAP authentication packets as a list of timestamps
            "IMAP DoS": defaultdict(list),  # Dictionary to store IMAP DoS packets as a list of timestamps
            "POP3 Authentication": defaultdict(list),  # Dictionary to store POP3 authentication packets as a list of timestamps
            "POP3 Data Exfiltration": defaultdict(list)  # Dictionary to store POP3 DoS packets as a list of timestamps
        }
        self.UDP = {
            "DNS": {
                "Query": None,  # Will store the IP address of the DNS query
                "Response": None,  # Will store the IP address of the DNS response
                "ID": {},  # Will store the ID of the DNS queries and False to represent that the response has not been received
                "Suspected Tunneling": defaultdict(list) # Dictionary to store suspected DNS tunneling packets as a list of timestamps
            },
            "MDNS": False,
            "DHCP": {
                "ID": []
            },
        }

        self.ICMP = {
            "Request": False,   # Boolean to store if ICMP request packet is detected
            "High Traffic": defaultdict(list), # Dictionary to store high traffic ICMP packets as a list of timestamps
            "Traceroute": defaultdict(list),  # Dictionary to store traceroute ICMP packets as a list of timestamps
            "Destination Unreachable": defaultdict(list),  # Dictionary to store destination unreachable ICMP packets as a list of timestamps
            "IPv6 Packets": defaultdict(list),  # Dictionary to store IPv6 ICMP packets as a list of timestamps
            "IPv6 Traceroute": defaultdict(list),  # Dictionary to store IPv6 traceroute ICMP packets as a list of timestamps
            "IPv6 Redirect": defaultdict(list),  # Dictionary to store IPv6 redirect ICMP packets as a list of timestamps
            "IPv6 Amplification": defaultdict(list)  # Dictionary to store IPv6 amplification ICMP packets as a list of timestamps
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

            self.logger.info(f"Initializing packet analysis for packet: {packet.summary()}")
            self.analyze_packet(packet)

    def update_packet(self, packet: scapy.Packet):
        self.num_of_packets += 1
        self.total_data += len(packet)
        self.analyze_packet(packet)

    def analyze_packet(self, packet: scapy.Packet):
        # Check if it's an IP packet (IPv4)
        if ARP in packet:
            self.process_mac(packet)

        if IP in packet:
            # Handle TCP
            if packet.haslayer(TCP):
                self.process_tcp(packet)
            elif packet.haslayer(UDP):
                self.process_udp(packet)
            elif packet.haslayer(ICMP):
                self.process_icmp(packet)
        elif IPv6 in packet:
           if packet.haslayer(ICMPv6Unknown):
               self.process_icmpv6(packet)

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

        self.check_dos(packet)  # Check for DoS attack

        # Check for protocols that use TCP:
        if SSH in packet:
            self.process_ssh(packet)

        elif HTTP in packet:  # Check for HTTP
            self.process_http(packet)

        tcp_layer = packet[TCP]
        if tcp_layer.dport == 21 or tcp_layer.sport == 21 or tcp_layer.dport == 20 or tcp_layer.sport == 20:
            self.process_ftp(packet)

        if packet[TCP].dport == 445 or packet[TCP].sport == 445:  # SMB port (default 445)
            self.process_smb(packet)

        if packet[TCP].dport == 143 or packet[TCP].sport == 143:  # Check for IMAP port (default 143)
            self.process_imap(packet)

        if packet[TCP].dport == 110 or packet[TCP].sport == 110:  # Check for POP3 port (default 110)
            self.process_pop3(packet)


    def process_pop3(self, packet: scapy.Packet):
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode('utf-8', errors='ignore')  # Get the raw payload as text
            # Detect authentication failure (repeated incorrect USER/PASS commands)
            if "USER" in data and "PASS" in data:
                if "incorrect" in data.lower():  # Looking for "incorrect" in the response, which usually indicates failure
                    self.check_times(self.TCP["POP3 Authentication"], PacketAnalyzer.get_sender_ip(packet),
                                     timedelta(seconds=5), 20,
                                     anomaly_type="POP3 Abnormality", description="Suspected brute force/scanning",
                                     level=AbnormalityType.WARNING)
            if "RETR" in data:
                self.check_times(self.TCP["POP3 Data Exfiltration"], PacketAnalyzer.get_sender_ip(packet),
                                 timedelta(seconds=5), 30,
                                 anomaly_type="POP3 Abnormality", description="Suspected command flooding/Data Exfiltration",
                                 level=AbnormalityType.WARNING)

    def process_imap(self, packet: scapy.Packet):
        # Check for IMAP commands
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode('utf-8', errors='ignore')  # Get the raw payload as text
            if "LOGIN" in data:
                if "NO" in data.upper():  # Check for failed login response (usually "NO" in IMAP)
                    self.check_times(self.TCP["IMAP Authentication"], PacketAnalyzer.get_sender_ip(packet),
                                     timedelta(seconds=5), 20,
                                     anomaly_type="IMAP Abnormality", description="Suspected brute force",
                                     level=AbnormalityType.WARNING)

            # Detect command flooding: Multiple rapid commands
            if "SELECT" in data or "FETCH" in data or "LOGIN" in data:
                self.check_times(self.TCP["IMAP DoS"], PacketAnalyzer.get_sender_ip(packet),
                                 timedelta(seconds=5), 30, anomaly_type="IMAP Abnormality",
                                 description="Suspected command flooding", level=AbnormalityType.WARNING)

    def process_smb(self, packet: scapy.Packet):
        if packet.haslayer(Raw):
            data = packet[Raw].load

            if b"SMB_COM_SESSION_SETUP" in data:
                if b"STATUS_ACCESS_DENIED" in data.upper():  # Common failure status
                    self.check_times(self.TCP["SMB Authentication"], PacketAnalyzer.get_sender_ip(packet),
                                     timedelta(seconds=5), 20, anomaly_type="SMB Abnormality",
                                     description="Suspected brute force", level=AbnormalityType.WARNING)

            # Detect suspicious access to administrative shares (e.g., C$, ADMIN$)
            suspicious_shares = ["C$", "ADMIN$", "IPC$", "ADMIN"]
            if any(share in data.decode(errors="ignore") for share in suspicious_shares):
                anomaly = FlowAbnormality(
                    abnormality_type="SMB Abnormality",
                    description=f"Suspicious access to share detected: {data.decode(errors='ignore')}",
                    level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)

    def process_ftp(self, packet: scapy.Packet):
        # Check for brute force attack
        self.logger.info("Processing FTP packet")
        TIME_WINDOW = timedelta(seconds=5)
        ATTEMPTS = 60
        self.check_times(self.TCP["FTP"], PacketAnalyzer.get_sender_ip(packet), TIME_WINDOW, ATTEMPTS,
                         anomaly_type="FTP Abnormality", description="Brute force attack detected",
                         level=AbnormalityType.ALERT)


    def process_ssh(self, packet: scapy.Packet):
        # TODO: Test functionality
        self.logger.info("Processing SSH packet")

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
        src_ip = PacketAnalyzer.get_sender_ip(packet)   # Modular for both IP and IPv6
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

        if tcp_layer.flags & (PSH | ACK):  # Flags for payload transfer
            payload_size = len(packet[TCP].payload)
            if payload_size > 2000:  # Large payload size
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

        TIME_WINDOW = timedelta(seconds=60)
        NARROW_TIME_WINDOW = timedelta(seconds=10)
        DNS_REQUEST_THRESHOLD = 50
        MAX_QUERY_LENGTH = 100
        DNS_TUNNELING_THRESHOLD = 10

        dns = packet[DNS]  # Take the DNS layer of the packet

        self.process_dns_header(packet)

        if dns.qr == 0:  # Query packet
            self.UDP["DNS"]["Query"] = PacketAnalyzer.get_sender_ip(packet)
            domain_name = dns.qd.qname.decode("utf-8") if packet[DNS].qd else ""
            # Extract domain and suffix using tldextract
            extracted = tldextract.extract(domain_name)
            simplified_domain = f"{extracted.domain}.{extracted.suffix}"  # Combine domain and suffix
            self.logger.info(f"Parsed domain: {simplified_domain}")

            # Check for DNS tunneling by checking if the domain name has been requested before
            if simplified_domain not in self.__requestedDomains:  # Check if the domain name has been requested before (DNS Tunneling)
                self.__requestedDomains.append(simplified_domain)
            else:
                self.check_times(self.UDP["DNS"]["Suspected Tunneling"], PacketAnalyzer.get_sender_ip(packet),
                                 NARROW_TIME_WINDOW, DNS_TUNNELING_THRESHOLD, anomaly_type="DNS Abnormality",
                                 description="Potential DNS tunneling detected", level=AbnormalityType.WARNING)

            # Check for DNS packet ID reuse (transaction ID)
            if dns.id in self.UDP["DNS"]["ID"].keys():
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS packet ID is reused",
                                          level=AbnormalityType.TRANSACTION_VIOLATION)
                self.add_abnormality(anomaly)
            else:
                self.UDP["DNS"]["ID"][dns.id] = False

            src_ip = PacketAnalyzer.get_sender_ip(packet)
            self.check_times(self.UDP["DNS"]["Suspected Tunneling"], src_ip, TIME_WINDOW, DNS_REQUEST_THRESHOLD,
                             anomaly_type="DNS Abnormality", description="Potential DNS tunneling detected",
                             level=AbnormalityType.WARNING)

            # Get the domain name being queried
            if len(domain_name) > MAX_QUERY_LENGTH:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="Long DNS query detected",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)
            # TODO: Remove this code
            # current_time = datetime.now()
            #
            # # Append the current time to the list of timestamps for the source IP
            # self.UDP["DNS"]["Suspected Tunneling"][src_ip].append(current_time)
            #
            # # Remove timestamps that are outside of the time window
            # self.UDP["DNS"]["Suspected Tunneling"][src_ip] = [timestamp for timestamp in
            #                                                   self.UDP["DNS"]["Suspected Tunneling"][src_ip] if
            #                                                   current_time - timestamp < TIME_WINDOW]
            #
            # # Check if the number of requests exceeds the threshold
            # if len(self.UDP["DNS"]["Suspected Tunneling"][src_ip]) > DNS_REQUEST_THRESHOLD:
            #     anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
            #                                 description="Potential DNS tunneling detected",
            #                                 level=AbnormalityType.WARNING)
            #     self.add_abnormality(anomaly)

        elif dns.qr == 1:  # Response packet
            if not self.UDP["DNS"]["Query"]:  # Check if there was a query before the response
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS response without a query",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)
            self.UDP["DNS"]["Response"] = PacketAnalyzer.get_sender_ip(packet)

            # Check if the query and response are from the same IP
            if self.UDP["DNS"]["Query"] == self.UDP["DNS"]["Response"]:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS query and response are from the same IP",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)


            # Add the resolved IP to the list of resolved IPs
            for address in dns.an:
                self.__resolvedIPs.append(address)
            for address in dns.ns:
                self.__resolvedIPs.append(address)
            for address in dns.ar:
                self.__resolvedIPs.append(address)

            # Check for a query response mismatch
            if dns.id not in self.UDP["DNS"]["ID"].keys():
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS ID does not match any query",
                                          level=AbnormalityType.TRANSACTION_VIOLATION)
                self.add_abnormality(anomaly)
            elif dns.id in self.UDP["DNS"]["ID"].keys() and not self.UDP["DNS"]["ID"][dns.id]:
                self.UDP["DNS"]["ID"][dns.id] = True
            elif dns.id in self.UDP["DNS"]["ID"].keys() and self.UDP["DNS"]["ID"][dns.id]:
                anomaly = FlowAbnormality(abnormality_type="DNS Abnormality",
                                          description="DNS ID is reused",
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


    def process_dhcp(self, packet: scapy.Packet) -> None:
        """
        This function processes DHCP packets and checks for abnormalities
        :param packet: the DHCP packet to check
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
        if bootp.xid in self.UDP["DHCP"]["ID"]:
            anomaly = FlowAbnormality(abnormality_type="DHCP Abnormality",
                                      description="Transaction ID is reused",
                                      level=AbnormalityType.TRANSACTION_VIOLATION)
            self.add_abnormality(anomaly)
        else:
            self.UDP["DHCP"]["ID"].append(bootp.xid)

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


    def process_http(self, packet: scapy.Packet):
        # Check if the IP is in the resolved IPs list
        if packet[IP].dst not in self.__resolvedIPs:
            anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                      description="Packet IP address is not in the resolved IPs list",
                                      level=AbnormalityType.WARNING)
            self.add_abnormality(anomaly)

        if packet[TCP].sport != 80 and packet[TCP].dport != 80:
            anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                      description="HTTP packet is not on standard port 80",
                                      level=AbnormalityType.PORT_VIOLATION)
            self.add_abnormality(anomaly)

        if packet.haslayer(HTTPRequest):
            http_request = packet[HTTPRequest]
            if not http_request.Method or not http_request.Host:
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="HTTP request missing method or host",
                                          level=AbnormalityType.HEADER_VIOLATION)
                self.add_abnormality(anomaly)

                # Check for unusual HTTP methods
            valid_methods = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}
            if http_request.Method.decode() not in valid_methods:
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="Unusual HTTP method",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)

            # Check for overly long URL
            if len(http_request.Path) > 2000:
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="Overly long URL",
                                          level=AbnormalityType.PAYLOAD_VIOLATION)
                self.add_abnormality(anomaly)

            # Check for unusual headers
            if b"User-Agent" not in http_request.fields:
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="Missing User-Agent header",
                                          level=AbnormalityType.HEADER_VIOLATION)
                self.add_abnormality(anomaly)

        if packet.haslayer(HTTPResponse):
            http_response = packet[HTTPResponse]

            # Check for unusual status codes
            if http_response.Status_Code not in range(100, 600):
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="Unusual HTTP status code",
                                          level=AbnormalityType.WARNING)
                self.add_abnormality(anomaly)

            # Check for overly long response
            if len(http_response) > 2000:
                anomaly = FlowAbnormality(abnormality_type="HTTP Abnormality",
                                          description="Overly long HTTP response",
                                          level=AbnormalityType.PAYLOAD_VIOLATION)
                self.add_abnormality(anomaly)


    def process_mac(self, packet: scapy.Packet) -> None:
        """
        This function checks for IP-MAC mismatches.
        :param packet: The packet to check
        """
        arp_layer = packet[ARP]
        if arp_layer.op == 2:  # ARP Reply (op=2)
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc

            # Check for mismatches
            if src_ip in self.__arp_table.keys():
                if self.__arp_table[src_ip] != src_mac:
                    anomaly = FlowAbnormality(abnormality_type="ARP Spoofing",
                                              description=f"IP: {src_ip}, Expected MAC: {self.__arp_table[src_ip]},"
                                                          f" Seen MAC: {src_mac}",
                                              level=AbnormalityType.ALERT)
                    self.add_abnormality(anomaly)
            else:
                # Add to ARP table
                self.__arp_table[src_ip] = src_mac

        elif packet.haslayer(IP) and packet.haslayer(Ether):  # Check for Ethernet traffic
            src_ip = packet[IP].src
            src_mac = packet[Ether].src

            # Validate IP-MAC mapping
            if src_ip in self.__arp_table.keys() and self.__arp_table[src_ip] != src_mac:
                anomaly = FlowAbnormality(abnormality_type="IP-MAC mismatch",
                                          description=f"IP: {src_ip}, Expected MAC: {self.__arp_table[src_ip]},"
                                                      f" Seen MAC: {src_mac}",
                                          level=AbnormalityType.ALERT)
                self.add_abnormality(anomaly)


    def check_dos(self, packet: scapy.Packet):
        # Check for a DoS attack
        SYN = 0x02
        RST = 0x04
        time_window = timedelta(seconds=10)
        THRESHOLD = 50

        if TCP in packet:
            src_ip = PacketAnalyzer.get_sender_ip(packet)
            # Check for abnormal amount of SYN packets
            if packet[TCP].flags & SYN:
                self.check_times(self.TCP["SYN Packets"], src_ip, time_window, THRESHOLD,
                                 "SYN Flood Attack", f"More than {THRESHOLD} SYN packets in"
                                                     f" {time_window} seconds", AbnormalityType.ALERT)
                # TODO: Remove this code
                # self.TCP["SYN Packets"][src_ip].append(datetime.now())
                # # Update the list of SYN packets with recent packets
                # now = datetime.now()
                # self.TCP["SYN Packets"][src_ip] = [t for t in self.TCP["SYN Packets"][src_ip] if now - t < time_window]
                # if len(self.TCP["SYN Packets"]) > THRESHOLD:
                #     anomaly = FlowAbnormality(abnormality_type="SYN Flood Attack",
                #                               description=f"More than {THRESHOLD} SYN packets in {time_window} seconds",
                #                               level=AbnormalityType.ALERT)
                #     self.add_abnormality(anomaly)
                #     del self.TCP["SYN Packets"][src_ip]  # Reset after reporting

            # Check for abnormal amount of RST packets
            if packet[TCP].flags & RST:
                self.check_times(self.TCP["RST Packets"], src_ip, time_window, THRESHOLD,
                                 "RST Flood Attack", f"More than {THRESHOLD} RST packets in "
                                                     f"{time_window} seconds", AbnormalityType.ALERT)
                # TODO: Remove this code
                # self.TCP["RST Packets"][src_ip].append(datetime.now())
                # # Update the list of RST packets with recent packets
                # now = datetime.now()
                # self.TCP["RST Packets"][src_ip] = [t for t in self.TCP["RST Packets"][src_ip] if now - t < time_window]
                # if len(self.TCP["RST Packets"]) > THRESHOLD:
                #     anomaly = FlowAbnormality(abnormality_type="DoS Attack",
                #                               description=f"More than {THRESHOLD} RST packets in {time_window} seconds",
                #                               level=AbnormalityType.ALERT)
                #     self.add_abnormality(anomaly)
                #     del self.TCP["RST Packets"][src_ip]

    def process_icmp(self, packet):
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]
        # Detect high traffic rate (example: implement rate counter elsewhere)
        # Detect unusual types or codes
        if icmp_layer.type not in [0, 3, 8, 11]:
            anomaly = FlowAbnormality(abnormality_type="ICMP Abnormality",
                                        description=f"Unusual ICMP type detected: {icmp_layer.type}",
                                        level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)
        # Detect redirect messages
        if icmp_layer.type == 5:
            anomaly = FlowAbnormality(abnormality_type="ICMP Abnormality",
                                        description=f"ICMP Redirect detected from {ip_layer.src} to {ip_layer.dst}",
                                        level=AbnormalityType.ALERT)
            self.add_abnormality(anomaly)
        # Detect ping amplification (broadcast requests)
        if icmp_layer.type == 8 and ip_layer.dst.endswith(".255"):
            anomaly = FlowAbnormality(abnormality_type="ICMP Abnormality",
                                        description=f"Potential ICMP amplification: {ip_layer.src} -> {ip_layer.dst}",
                                        level=AbnormalityType.WARNING)
            self.add_abnormality(anomaly)
        # Detect oversized packets (Ping of Death)
        if len(packet) > 65535:
            anomaly = FlowAbnormality(abnormality_type="ICMP Abnormality",
                                        description=f"Ping of Death detected from {ip_layer.src} to {ip_layer.dst}",
                                        level=AbnormalityType.PAYLOAD_VIOLATION)
            self.add_abnormality(anomaly)
        # Detect traceroute (TTL exceeded)
        if icmp_layer.type == 11:
            src_ip = ip_layer.src
            self.check_times(self.ICMP["Traceroute"], src_ip, timedelta(seconds=10), 50, "ICMP Abnormality",
                             "Potential traceroute detected", AbnormalityType.WARNING)

        # Detect ICMP echo reply without echo request
        if icmp_layer.type == 0 and not self.ICMP["Request"]:
            anomaly = FlowAbnormality(abnormality_type="ICMP Abnormality",
                                      description="ICMP Echo Reply without Echo Request",
                                      level=AbnormalityType.ALERT)
            self.add_abnormality(anomaly)
        elif icmp_layer.type == 0 and self.ICMP["Request"]:
            self.ICMP["Request"] = False

        if icmp_layer.type == 3 or icmp_layer.type == 4:
            self.check_times(self.ICMP["Destination Unreachable"], ip_layer.src, timedelta(seconds=5), 25,
                             "ICMP Abnormality",
                             "Potential flood or scanning activity", AbnormalityType.WARNING)

    def process_icmpv6(self, packet: scapy.Packet):
        icmpv6_layer = packet[ICMPv6Unknown]
        ip_layer = packet[IPv6]
        # Detect unusual types or codes
        if icmpv6_layer.type not in [1, 2, 3, 4, 128, 129, 133, 134, 135, 136]:
            anomaly = FlowAbnormality(abnormality_type="ICMPv6 Abnormality",
                                        description=f"Unusual ICMPv6 type detected: {icmpv6_layer.type}",
                                        level=AbnormalityType.HEADER_VIOLATION)
            self.add_abnormality(anomaly)

        # Detect high traffic rate
        self.check_times(self.ICMP["IPv6 Packets"], ip_layer.src, timedelta(seconds=5), 25, "ICMPv6 Abnormality",
                         "Potential flood or scanning activity", AbnormalityType.WARNING)
        # Detect redirect messages
        if packet.haslayer(ICMPv6ND_Redirect):
            self.check_times(self.ICMP["IPv6 Redirect"], ip_layer.src, timedelta(seconds=5), 10,
                             "ICMPv6 Abnormality",
                             "ICMPv6 Redirect detected (Possible MITM attack)", AbnormalityType.ALERT)
        # Detect ping amplification (broadcast requests)
        if packet.haslayer(ICMPv6ND_NS) and ip_layer.dst == "ff02::1":
            self.check_times(self.ICMP["IPv6 Amplification"], ip_layer.src, timedelta(seconds=2), 5, "ICMPv6 Abnormality",
                             "Potential ICMPv6 amplification", AbnormalityType.ALERT)

        # Detect oversized packets (Ping of Death)
        if len(packet) > 65535:
            anomaly = FlowAbnormality(abnormality_type="ICMPv6 Abnormality",
                                        description=f"Ping of Death detected from {ip_layer.src} to {ip_layer.dst}",
                                        level=AbnormalityType.PAYLOAD_VIOLATION)
            self.add_abnormality(anomaly)
        # Detect traceroute (TTL exceeded)
        if packet.haslayer(ICMPv6TimeExceeded):
            src_ip = ip_layer.src
            self.check_times(self.ICMP["IPv6 Traceroute"], src_ip, timedelta(seconds=5), 30, "ICMPv6 Abnormality",
                             "Potential traceroute detected", AbnormalityType.WARNING)

    def check_times(self, buffered_list: defaultdict[Any, list], src_ip, delta: timedelta, threshold: int,
                    anomaly_type: str, description: str, level: AbnormalityType) -> None:
        """
        This function checks for the number of packets in a given time window
        :param buffered_list: The list of timestamps to check
        :param src_ip: The source IP address
        :param delta: The time window to check
        :param threshold: The threshold for the number of packets
        :param anomaly_type: The type of anomaly
        :param description: The description of the anomaly
        :param level: The level of the anomaly
        """
        buffered_list[src_ip].append(datetime.now())
        now = datetime.now()

        buffered_list[src_ip] = [t for t in buffered_list[src_ip] if now - t < delta]
        if len(buffered_list[src_ip]) > threshold:
            anomaly = FlowAbnormality(abnormality_type=anomaly_type,
                                      description=description,
                                      level=level)
            self.add_abnormality(anomaly)
            del buffered_list[src_ip]


    def add_abnormality(self, anomaly: FlowAbnormality):
        if anomaly not in self.abnormalities.keys():
            self.abnormalities[anomaly] = 1
        else:
            self.abnormalities[anomaly] += 1


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

