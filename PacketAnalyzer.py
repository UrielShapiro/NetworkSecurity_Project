import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply

class PacketAnalyzer:
    @staticmethod
    def export_to_five_tuple(packet: scapy.Packet):
        # Initialize variables
        src_ip, dst_ip, src_port, dst_port, protocol = None, None, None, None, None

        # Check if it's an IP packet (IPv4)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto  # Protocol field from IP header

            # Handle TCP
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = TCP

            # Handle UDP
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = UDP

            # Handle ICMP (no ports)
            elif packet.haslayer(ICMP):
                protocol = ICMP
                # ICMP does not use ports, so no src_port or dst_port

        # Check if it's an IPv6 packet
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh  # Next Header field for protocol

            # Handle TCP
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = TCP

            # Handle UDP
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = UDP

            # Handle ICMPv6 (no ports)
            elif packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
                protocol = ICMPv6EchoRequest if packet.haslayer(ICMPv6EchoRequest) else ICMPv6EchoReply
                # ICMPv6 does not use ports

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}")
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        }