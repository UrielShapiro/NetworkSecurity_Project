import unittest

from PacketSniffer import read_pcap
from FlowAnalyzer import FlowAnalyzer


def analyze_pcap(pcap_path):
    analyzer = FlowAnalyzer()
    for packet in read_pcap(pcap_path):
        try:
            analyzer.add_packet(packet)
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    return analyzer.get_abnormalities()

class TestAnalyzer(unittest.TestCase):
    def test_normal_handshake(self):
        abnormalities = analyze_pcap("../pcaps/normal_handshake.pcap")
        self.assertEqual(len(list(abnormalities)), 0)

    def test_incomplete_handshake(self):
        abnormalities = analyze_pcap("../pcaps/incomplete_handshake.pcap")
        self.assertEqual(len(list(abnormalities)), 1)

    def test_syn_ack_only(self):
        abnormalities = analyze_pcap("../pcaps/syn_ack_only.pcap")
        self.assertEqual(len(list(abnormalities)), 1)

# Analyze both PCAPs
analyze_pcap("../pcaps/normal_handshake.pcap")
analyze_pcap("../pcaps/incomplete_handshake.pcap")
analyze_pcap("../pcaps/syn_ack_only.pcap")
