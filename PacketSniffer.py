from scapy.all import sniff, rdpcap, Packet
import sys

def sniff_packets(interface: str) -> Packet:
    packets = sniff(count=1, iface=interface)
    return packets[0]

def read_pcap(path: str) -> Packet:
    try:
        packets = rdpcap(path)
        for packet in packets:
            yield packet
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)