from PacketSniffer import read_pcap
from FlowAnalyzer import FlowAnalyzer

def analyze_pcap(pcap_path):
    analyzer = FlowAnalyzer()
    for packet in read_pcap(pcap_path):
        try:
            analyzer.add_packet(packet)
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    analyzer.print()

# Analyze both PCAPs
analyze_pcap("pcaps/normal_handshake.pcap")
analyze_pcap("pcaps/incomplete_handshake.pcap")
analyze_pcap("pcaps/syn_ack_only.pcap")
