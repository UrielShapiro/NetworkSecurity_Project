import os
from scapy.all import *
from scapy.layers.inet import IP, TCP

# Ensure the 'pcaps' directory exists
os.makedirs("../pcaps", exist_ok=True)


def create_normal_handshake(pcap_path):
    syn = IP(dst="192.168.1.1") / TCP(dport=80, flags="S", seq=1000)
    syn_ack = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    ack = IP(dst="192.168.1.1") / TCP(dport=80, flags="A", seq=1001, ack=2001)
    wrpcap(pcap_path, [syn, syn_ack, ack])


def create_incomplete_handshake(pcap_path):
    syn = IP(dst="192.168.1.1") / TCP(dport=80, flags="S", seq=1000)
    ack = IP(dst="192.168.1.1") / TCP(dport=80, flags="A", seq=1001, ack=2001)
    wrpcap(pcap_path, [syn, ack])


def create_syn_ack_only(pcap_path):
    # Create a packet with just SYN-ACK (abnormal as it lacks an initiating SYN)
    syn_ack = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=12345, flags="SA", seq=1000, ack=2001)
    wrpcap(pcap_path, [syn_ack])


# Generate PCAP files in the 'pcaps' directory
create_normal_handshake("../pcaps/normal_handshake.pcap")
create_incomplete_handshake("../pcaps/incomplete_handshake.pcap")
create_syn_ack_only("../pcaps/syn_ack_only.pcap")

print("PCAP files generated successfully!")
