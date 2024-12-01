from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6TimeExceeded, ICMPv6ND_Redirect
from scapy.layers.ssh import SSH
import os

# Directory to save pcap files
pcap_directory = "../pcaps"
os.makedirs(pcap_directory, exist_ok=True)

def create_pcap(packet, filename):
    filepath = os.path.join(pcap_directory, filename)
    wrpcap(filepath, packet)
    print(f"PCAP saved: {filepath}")

# 1. TCP SYN Flood Attack
packets = []
for i in range(60):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/TCP(sport=12345+i, dport=80, flags="S")
    packets.append(packet)
create_pcap(packets, "tcp_syn_flood.pcap")

# 2. DNS Tunneling Detection
packets = []
for i in range(20):
    packet = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname=f"sub{i}.example.com"))
    packets.append(packet)
create_pcap(packets, "dns_tunneling.pcap")

# 3. DHCP Transaction ID Reuse
packets = []
transaction_id = 0xabcdef12
for i in range(2):
    packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(xid=transaction_id)/DHCP(options=[("message-type", "discover"), "end"])
    packets.append(packet)
create_pcap(packets, "dhcp_transaction_id_reuse.pcap")

# 4. ICMP Redirect Detection
packet = IP(src="192.168.1.1", dst="192.168.1.100")/ICMP(type=5, code=1)/IP(src="192.168.1.200", dst="192.168.1.100")
create_pcap(packet, "icmp_redirect.pcap")

# 5. ARP Spoofing
packets = []
packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.100", hwsrc="00:11:22:33:44:55")
packets.append(packet)
packet = Ether(src="66:77:88:99:AA:BB", dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.100", hwsrc="66:77:88:99:AA:BB")
packets.append(packet)
create_pcap(packets, "arp_spoofing.pcap")

# 6. ICMP Ping of Death (Adjusted to avoid oversized packet error)
packet = IP(src="192.168.1.1", dst="192.168.1.100")/ICMP()/Raw(load="X"*65000)
create_pcap(packet, "icmp_ping_of_death.pcap")

# 7. IPv6 Amplification Attack
packets = []
for i in range(5):
    packet = IPv6(src=f"2001:db8::1{i}", dst="ff02::1")/ICMPv6EchoRequest()
    packets.append(packet)
create_pcap(packets, "ipv6_amplification.pcap")

# 8. TCP SYN-ACK without SYN (Handshake Anomaly)
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA")
create_pcap(packet, "tcp_syn_ack_without_syn.pcap")

# 9. DNS Response without Query
packet = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=12345)/DNS(qr=1, id=0xAAAA, qd=DNSQR(qname="example.com"))
create_pcap(packet, "dns_response_without_query.pcap")

# 10. POP3 Data Exfiltration
packets = []
for i in range(30):
    packet = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=110, dport=12345)/Raw(load="RETR secret_data")
    packets.append(packet)
create_pcap(packets, "pop3_data_exfiltration.pcap")

# 11. TCP FIN Scan
packets = []
for i in range(20):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/TCP(sport=12345+i, dport=80, flags="F")
    packets.append(packet)
create_pcap(packets, "tcp_fin_scan.pcap")

# 12. DHCP Starvation Attack
packets = []
for i in range(50):
    packet = Ether(src=f"00:11:22:33:44:{i:02x}", dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(xid=i)/DHCP(options=[("message-type", "discover"), "end"])
    packets.append(packet)
create_pcap(packets, "dhcp_starvation.pcap")

# 13. TCP Christmas Tree Packet
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=12345, dport=80, flags="FPU")
create_pcap(packet, "tcp_christmas_tree.pcap")

# 14. ICMP Flood Attack
packets = []
for i in range(100):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/ICMP()
    packets.append(packet)
create_pcap(packets, "icmp_flood.pcap")

# 15. HTTP GET Flood
packets = []
for i in range(50):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/TCP(sport=12345+i, dport=80, flags="PA")/Raw(load="GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
    packets.append(packet)
create_pcap(packets, "http_get_flood.pcap")

# 16. SSH Brute Force Attack
packets = []
for i in range(20):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/TCP(sport=22, dport=22, flags="S")/Raw(load="SSH-2.0-OpenSSH_7.9p1\n")
    packets.append(packet)
create_pcap(packets, "ssh_brute_force.pcap")

# 17. TCP RST Flood
packets = []
for i in range(50):
    packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100")/TCP(sport=12345+i, dport=80, flags="R")
    packets.append(packet)
create_pcap(packets, "tcp_rst_flood.pcap")

# 18. IPv6 ICMP Echo Request
packets = []
for i in range(5):
    packet = IPv6(src=f"2001:db8::1{i}", dst="2001:db8::100")/ICMPv6EchoRequest()
    packets.append(packet)
create_pcap(packets, "ipv6_icmp_echo_request.pcap")

# 19. IPv6 ICMP Echo Reply
packets = []
for i in range(5):
    packet = IPv6(src=f"2001:db8::100", dst=f"2001:db8::1{i}")/ICMPv6EchoReply()
    packets.append(packet)
create_pcap(packets, "ipv6_icmp_echo_reply.pcap")

# 20. DNS Cache Poisoning
packets = []
packet = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=12345)/DNS(qr=1, aa=1, id=0xAAAA, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", ttl=600, rdata="1.2.3.4"))
packets.append(packet)
create_pcap(packets, "dns_cache_poisoning.pcap")

# 21. FTP Brute Force Attack
packets = []
for i in range(20):
    packet = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=21, dport=21, flags="PA")/Raw(load="USER anonymous\r\nPASS password\r\n")
    packets.append(packet)
create_pcap(packets, "ftp_brute_force.pcap")

# 22. SMB Authentication Failure
packets = []
packet = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=445, dport=445, flags="PA")/Raw(load="SMB_COM_SESSION_SETUP_ANDX\x00STATUS_ACCESS_DENIED")
packets.append(packet)
create_pcap(packets, "smb_auth_failure.pcap")

# 23. IMAP Command Flooding
packets = []
for i in range(30):
    packet = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=143, dport=143, flags="PA")/Raw(load=f"SELECT INBOX{i}\r\n")
    packets.append(packet)
create_pcap(packets, "imap_command_flooding.pcap")

# 24. ICMPv6 Redirect Message
packet = IPv6(src="fe80::1", dst="fe80::2")/ICMPv6ND_Redirect()/IPv6(src="fe80::3", dst="fe80::4")
create_pcap(packet, "icmpv6_redirect.pcap")

# 25. TCP PSH Flag Alone
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=12345, dport=80, flags="P")
create_pcap(packet, "tcp_psh_flag_alone.pcap")

# 26. ICMP Time Exceeded (Traceroute)
packet = IP(src="192.168.1.1", dst="192.168.1.100", ttl=1)/ICMP(type=11, code=0)
create_pcap(packet, "icmp_time_exceeded.pcap")

# 27. DHCP Offer without Discover
packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.1", dst="255.255.255.255")/UDP(sport=67, dport=68)/BOOTP(xid=0xabcdef12)/DHCP(options=[("message-type", "offer"), "end"])
create_pcap(packet, "dhcp_offer_without_discover.pcap")

# 28. ICMP Destination Unreachable
packet = IP(src="192.168.1.1", dst="192.168.1.100")/ICMP(type=3, code=1)
create_pcap(packet, "icmp_destination_unreachable.pcap")

# 29. ARP Request Flood
packets = []
for i in range(100):
    packet = Ether(src=f"00:11:22:33:44:{i:02x}", dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc="192.168.1.1", pdst=f"192.168.1.{i+1}")
    packets.append(packet)
create_pcap(packets, "arp_request_flood.pcap")

# 30. ICMPv6 Time Exceeded
packet = IPv6(src="fe80::1", dst="fe80::2")/ICMPv6TimeExceeded()
create_pcap(packet, "icmpv6_time_exceeded.pcap")

# 31. TCP Three-Way Handshake Mismatch
packets = []
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=12345, dport=80, flags="S")
packets.append(packet)
packet = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=80, dport=12345, flags="SA")
packets.append(packet)
packet = IP(src="192.168.1.2", dst="192.168.1.1")/TCP(sport=80, dport=12345, flags="A")
packets.append(packet)
create_pcap(packets, "tcp_handshake_mismatch.pcap")

# 32. ICMPv6 Neighbor Solicitation
packet = IPv6(src="fe80::1", dst="ff02::1:ff00:2")/ICMPv6ND_NS(tgt="fe80::2")
create_pcap(packet, "icmpv6_neighbor_solicitation.pcap")

# 33. ICMPv6 Neighbor Advertisement
packet = IPv6(src="fe80::2", dst="fe80::1")/ICMPv6ND_NA(tgt="fe80::2", R=1, S=1, O=1)/IPv6(dst="fe80::1")
create_pcap(packet, "icmpv6_neighbor_advertisement.pcap")

# 34. DHCP ACK without Request
packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.1", dst="255.255.255.255")/UDP(sport=67, dport=68)/BOOTP(xid=0xabcdef12)/DHCP(options=[("message-type", "ack"), "end"])
create_pcap(packet, "dhcp_ack_without_request.pcap")

# 35. Suspicious HTTP Method (TRACE)
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=12345, dport=80, flags="PA")/Raw(load="TRACE / HTTP/1.1\r\nHost: target.com\r\n\r\n")
create_pcap(packet, "http_suspicious_method_trace.pcap")

# 36. SSH Large Payload
packet = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=22, dport=22, flags="PA")/Raw(load="X"*3000)
create_pcap(packet, "ssh_large_payload.pcap")

print("PCAP files for testing PacketAnalyzer have been generated.")
