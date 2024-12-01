import unittest
import os
from main import IDS


class TestIDSWithPCAPs(unittest.TestCase):
    pcap_directory = None

    @classmethod
    def setUpClass(cls):
        """Set up the PCAP directory for testing."""
        cls.pcap_directory = "../pcaps"
        os.makedirs(cls.pcap_directory, exist_ok=True)

    # def test_tcp_syn_flood(self):
    #     """Test the detection of a TCP SYN flood attack."""
    #     pcap_path = os.path.join(self.pcap_directory, "tcp_syn_flood.pcap")
    #     ids = IDS(sniff_flag=False, pcap_path=pcap_path)
    #     ids.set_test_mode(True)
    #     ids.start()
    #     ids.read_pcap()
    #     abnormalities = ids.get_abnormalities()
    #     self.assertGreater(len(list(abnormalities)), 0, "Failed to detect TCP SYN flood attack")
    #     ids.stop()

    # def test_dns_tunneling(self):
    #     """Test the detection of DNS tunneling."""
    #     pcap_path = os.path.join(self.pcap_directory, "dns_tunneling.pcap")
    #     ids = IDS(sniff_flag=False, pcap_path=pcap_path)
    #     ids.set_test_mode(True)
    #     ids.start()
    #     ids.read_pcap()
    #     abnormalities = ids.get_abnormalities()
    #     self.assertGreater(len(list(abnormalities)), 0, "Failed to detect DNS tunneling")
    #     ids.stop()

    # def test_dhcp_transaction_id_reuse(self):
    #     """Test the detection of DHCP transaction ID reuse."""
    #     pcap_path = os.path.join(self.pcap_directory, "dhcp_transaction_id_reuse.pcap")
    #     ids = IDS(sniff_flag=False, pcap_path=pcap_path)
    #     ids.set_test_mode(True)
    #     ids.start()
    #     ids.read_pcap()
    #     abnormalities = ids.get_abnormalities()
    #     self.assertGreater(len(list(abnormalities)), 0, "Failed to detect DHCP transaction ID reuse")
    #     ids.stop()

    def test_arp_spoofing(self):
        """Test the detection of ARP spoofing."""
        pcap_path = os.path.join(self.pcap_directory, "arp_spoofing.pcap")
        ids = IDS(sniff_flag=False, pcap_path=pcap_path, sniff_interface=None)
        ids.set_test_mode(True)
        ids.start()
        abnormalities = ids.get_abnormalities()
        self.assertGreater(len(list(abnormalities)), 0, "Failed to detect ARP spoofing")
        ids.stop()

    # def test_icmp_redirect(self):
    #     """Test the detection of ICMP redirect packets."""
    #     pcap_path = os.path.join(self.pcap_directory, "icmp_redirect.pcap")
    #     ids = IDS(sniff_flag=False, pcap_path=pcap_path)
    #     ids.set_test_mode(True)
    #     ids.start()
    #     ids.read_pcap()
    #     abnormalities = ids.get_abnormalities()
    #     self.assertGreater(len(list(abnormalities)), 0, "Failed to detect ICMP redirect packet")
    #     ids.stop()

    # def test_http_get_flood(self):
    #     """Test the detection of an HTTP GET flood."""
    #     pcap_path = os.path.join(self.pcap_directory, "http_get_flood.pcap")
    #     ids = IDS(sniff_flag=False, pcap_path=pcap_path)
    #     ids.set_test_mode(True)
    #     ids.start()
    #     ids.read_pcap()
    #     abnormalities = ids.get_abnormalities()
    #     self.assertGreater(len(list(abnormalities)), 0, "Failed to detect HTTP GET flood")
    #     ids.stop()

    # Add more tests for each generated PCAP file

if __name__ == "__main__":
    unittest.main()
