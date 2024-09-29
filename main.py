import sys

import scapy.all as scapy
from scapy.layers.inet import UDP, TCP, IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.utils import rdpcap
from PacketFlow import PacketFlow

def main(argv):
    try:
        packets = rdpcap(argv)
        flow = dict()
        for packet in packets:
            five_tuple = process_packet(packet)
            if five_tuple in flow:
                flow[five_tuple].update_packet(packet)
            else:
                flow[five_tuple] = PacketFlow(packet)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

def process_packet(packet: scapy.Packet):
    # Initialize variables
    src_ip, dst_ip, src_port, dst_port, protocol = None, None, None, None, None

    # Check if it's an IP packet (IPv4)
    if IP in packet:
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <pcap_file>")
        sys.exit(1)
    main(sys.argv[1])