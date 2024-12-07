from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.ssh import SSH


def create_tcp_packet(ip_src, ip_dst, sport, dport, flags):
    """Helper function to create TCP packets."""
    ip = IP(src=ip_src, dst=ip_dst)
    tcp = TCP(sport=sport, dport=dport, flags=flags)
    return ip / tcp


def generate_tcp_pcap(file_name):
    packets = []

    # 1. All flags set together
    pkt1 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "FSRPAUEC")  # All flags set
    packets.append(pkt1)

    # 2. SYN, ACK, and FIN flags together
    pkt2 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "SAF")  # SYN, ACK, FIN
    packets.append(pkt2)

    # 3. SYN and FIN flags together
    pkt3 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "SF")  # SYN, FIN
    packets.append(pkt3)

    # 4. SYN and RST flags together
    pkt4 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "SR")  # SYN, RST
    packets.append(pkt4)

    # 5. FIN and RST flags together
    pkt5 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "FR")  # FIN, RST
    packets.append(pkt5)

    # 6. Only FIN flag set
    pkt6 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "F")  # Only FIN
    packets.append(pkt6)

    # 7. Only PSH flag set
    pkt7 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "P")  # Only PSH
    packets.append(pkt7)

    # 8. Only URG flag set
    pkt8 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "U")  # Only URG
    packets.append(pkt8)

    # 9. SYN flag without ACK (Initial SYN)
    pkt9 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "S")  # SYN only
    packets.append(pkt9)

    # 10. SYN-ACK flag after SYN
    pkt10 = create_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, "SA")  # SYN-ACK
    packets.append(pkt10)

    # 11. ACK flag after SYN and SYN-ACK (Three-way handshake)
    pkt11 = create_tcp_packet("192.168.1.2", "192.168.1.1", 12345, 80, "A")  # ACK
    packets.append(pkt11)

    # 12. TCP handshake anomalies
    pkt12 = create_tcp_packet("192.168.1.1", "192.168.1.3", 12345, 80, "S")  # SYN from one sender
    pkt13 = create_tcp_packet("192.168.1.3", "192.168.1.1", 12345, 80, "SA")  # SYN-ACK from another sender
    pkt14 = create_tcp_packet("192.168.1.2", "192.168.1.1", 12345, 80, "A")  # ACK from yet another sender
    packets.extend([pkt12, pkt13, pkt14])

    # Save the packets to a pcap file
    wrpcap(file_name, packets)


def create_pop3_imap_smb_packet(ip_src, ip_dst, sport, dport, data):
    """Helper function to create POP3 packets with Raw payload."""
    ip = IP(src=ip_src, dst=ip_dst)
    tcp = TCP(sport=sport, dport=dport)
    raw_data = Raw(load=data)
    return ip / tcp / raw_data


def generate_pop3_pcaps(prefix):
    # Create multiple packets for POP3 Authentication Failure (incorrect USER/PASS)
    failure_data = "USER testuser\r\nPASS incorrectpassword\r\nincorrect login"
    auth_fail_packets = []
    for i in range(500):
        auth_fail_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, failure_data))
    wrpcap(f"{prefix}pop3_authentication_failure.pcap", auth_fail_packets)

    # Create multiple packets for POP3 Data Exfiltration (RETR command)
    retr_data = "RETR 1\r\n"
    retr_packets = []
    for i in range(100):
        retr_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, retr_data))
    wrpcap(f"{prefix}pop3_data_exfiltration.pcap", retr_packets)

    # Create multiple failed authentication attempts for brute force simulation
    brute_force_data = "USER testuser\r\nPASS incorrectpassword\r\nincorrect login"
    brute_force_packets = []
    for i in range(500):
        brute_force_packets.append(
            create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, brute_force_data))
    wrpcap(f"{prefix}multiple_pop3_authentication_failures.pcap", brute_force_packets)

    # Create multiple RETR commands for command flooding/data exfiltration simulation
    retr_flood_data = "RETR 1\r\n"
    retr_flood_packets = []
    for i in range(100):
        retr_flood_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, retr_flood_data))
    wrpcap(f"{prefix}multiple_retr_commands.pcap", retr_flood_packets)


def generate_imap_pcaps(prefix):
    # Create multiple packets for IMAP Authentication Failure (failed LOGIN)
    login_failure_data = "LOGIN user password NO\r\n"
    auth_fail_packets = []
    for i in range(500):
        auth_fail_packets.append(
            create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 143, 143, login_failure_data))
    wrpcap(f"{prefix}imap_authentication_failure.pcap", auth_fail_packets)

    # Create multiple packets for IMAP Command Flooding (SELECT, FETCH, LOGIN commands)
    command_flood_data = ["SELECT inbox\r\n", "FETCH 1:* (FLAGS)\r\n", "LOGIN user\r\n"]
    command_flood_packets = []
    for i in range(100):
        command_flood_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 143, 143,
                                                                 command_flood_data[random.randint(0, 2)]))
    wrpcap(f"{prefix}imap_command_flooding.pcap", command_flood_packets)


def generate_smb_pcaps(prefix):
    auth_fail_data = (
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # SMB Header (typically varies)
            + b"SMB_COM_SESSION_SETUP\x00\x00"  # SMB Command and Setup
            + b"STATUS_ACCESS_DENIED"  # Simulating the 'ACCESS DENIED' failure
    )
    # Generate 500 packets with failed authentication
    auth_fail_packets = []
    for i in range(500):
        auth_fail_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 445, 445, auth_fail_data))
    wrpcap(f"{prefix}smb_authentication_failure.pcap", auth_fail_packets)

    # Create packets for suspicious access to administrative shares (C$, ADMIN$, IPC$, ADMIN)
    suspicious_access_data = [b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00ADMIN$",
                              b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00C$",
                              b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00ADMIN",
                              b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00IPC$"]
    suspicious_access_packets = []
    for i in range(500):
        suspicious_access_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 445, 445,
                                                                     suspicious_access_data[random.randint(0, 3)]))
    wrpcap(f"{prefix}smb_suspicious_access.pcap", suspicious_access_packets)


def create_ftp_packet(src_ip, dst_ip, sport, dport, payload):
    """
    Create a custom FTP packet with the given parameters.
    """
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=sport, dport=dport, seq=1000, ack=1001, flags='PA')
    raw_layer = Raw(load=payload)
    return ip_layer / tcp_layer / raw_layer


def generate_ftp_pcap(prefix):
    src_ip = "192.168.1.10"
    dst_ip = "192.168.1.20"
    sport = 1025
    dport = 21  # FTP default port
    packets = []

    # Create multiple packets within a short time window to simulate brute force
    for i in range(100):  # More than the threshold of 60
        payload = f"USER user{i}\r\nPASS password{i}\r\n".encode('utf-8')
        ftp_packet = create_ftp_packet(src_ip, dst_ip, sport, dport, payload)
        packets.append(ftp_packet)

    filename = f"{prefix}ftp_bruteforce.pcap"
    wrpcap(filename, packets)


def create_ssh_packet(src_ip, dst_ip, sport, dport, flags, payload=b"SSH-2.0-OpenSSH_8.6p1 Ubuntu-6ubuntu0.1\r\n"):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=sport, dport=dport, flags=flags)
    ssh_layer = SSH(payload)
    return ip_layer / tcp_layer / ssh_layer


def generate_ssh_pcap(prefix):
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"
    standard_port = 22
    non_standard_port = 2222
    PSH = 0x08
    ACK = 0x10
    RST = 0x04
    SYN = 0x02
    packets = []

    # Case 1: SSH on non-standard port
    for _ in range(1):
        large_payload = b"A" * 2500  # Payload size > 2000 bytes

        # ssh_packet = create_ssh_packet(src_ip, dst_ip, sport=1234, dport=non_standard_port, flags=(PSH | ACK))
        ssh_packet = create_ssh_packet(src_ip, dst_ip, sport=1234, dport=non_standard_port, flags=(PSH | ACK),
                                       payload=large_payload)
        packets.append(ssh_packet)
    wrpcap(f"{prefix}ssh_non_standard_port.pcap", packets)

    packets.clear()

    # Case 2: Brute-force attempts (multiple TCP RST packets)
    for _ in range(15):  # More than the threshold of 10
        ssh_packet = create_ssh_packet(src_ip, dst_ip, sport=1234, dport=standard_port, flags=(PSH | ACK))
        packets.append(ssh_packet)

    wrpcap(f"{prefix}ssh_bruteforce.pcap", packets)

    packets.clear()

    # Case 3: Large SSH payload
    large_payload = b"A" * 2500  # Payload size > 2000 bytes
    ssh_packet = create_ssh_packet(src_ip, dst_ip, sport=1234, dport=standard_port, flags=(PSH | ACK),
                                   payload=large_payload)
    packets.append(ssh_packet)

    wrpcap(f"{prefix}ssh_large_payload.pcap", packets)


# Function to generate a random domain name for DNS queries
def random_domain():
    return ''.join(random.choices(string.ascii_lowercase, k=10)) + ".com"


def generate_dns_query(src_ip, dst_ip, domain, dst_port=53, src_port=53, transaction_id=1234):
    return Ether() / IP(dst=dst_ip, src=src_ip) / UDP(dport=dst_port, sport=src_port) / DNS(qr=0,
                                                                                            qd=DNSQR(qname=domain),
                                                                                            id=transaction_id)


def generate_dns_response(src_ip, dst_ip, sport, dport, domain, ip, transaction_id=1234):
    return Ether() / IP(dst=dst_ip, src=src_ip) / UDP(dport=dport, sport=sport) / DNS(qr=1,
                                                                                      an=DNSRR(rrname=domain, rdata=ip),
                                                                                      id=transaction_id)


# DNS Query with long query (exceeding MAX_QUERY_LENGTH)
def generate_long_dns_query():
    return generate_dns_query("192.168.1.1", "8.8.8.8", "a.com" * 1000)


# DNS Response without query
def generate_dns_response_without_query():
    return generate_dns_response("8.8.8.8", "192.168.1.1", 53, random.randint(1024, 65535), "example.com", "127.0.0.1",
                                 1234)


# DNS Response with reused transaction ID
def generate_dns_response_reused_id():
    packets = []
    for _ in range(2):
        packets.append(generate_dns_response("8.8.8.8", "192.168.1.1", 53, 1234, random_domain(), "192.168.1.1", 1234))
    return packets


# DNS Query for potential tunneling (same domain multiple times)
def generate_dns_query_for_tunneling():
    packets = []
    for _ in range(10):
        dns_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        packets.append(dns_packet)
    return packets


def generate_dns_query_and_response_from_the_same_ip():
    packets = []
    packets.append(generate_dns_query("192.168.1.10", "8.8.8.8", "example.com"))
    packets.append(generate_dns_response("192.168.1.10", "8.8.8.8", 53, 53, "example.com", "123.123.1.2"))
    return packets


def generate_mdns_packet_not_authoritative():
    return IP(src="224.0.0.251", dst="192.168.1.10") / UDP(sport=5353, dport=5353) / DNS(
        id=1,
        qr=1,  # Response
        aa=0,  # Not authoritative
        qd=DNSQR(qname="_services._dns-sd._udp.local"),
        an=DNSRR(rrname="_services._dns-sd._udp.local", rdata="192.168.1.20"))


def generate_dns_query_not_on_port_53():
    return generate_dns_query("127.0.0.1", "123.123.1.1", "example.com", random.randint(1024, 2000),
                              random.randint(1024, 2000))


def generate_dns_not_standard_query():
    return IP(dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(opcode=1, qd=DNSQR(qname="example.com"))


def generate_dns_suspicious_number_of_queries():
    questions = [DNSQR(qname=f"example{i}.com") for i in range(11)]  # 11 questions
    return IP(dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(qd=questions)


def generate_dns_suspicious_number_of_answers():
    answers = [DNSRR(rrname="example.com", rdata=f"192.168.1.{i}") for i in range(21)]  # 21 answers
    return IP(dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(ancount=21, an=answers)


# Main function to generate the pcap files
def generate_dns_pcap(prefix):
    # Test case: DNS query with long query
    wrpcap(f"{prefix}dns_query_long.pcap", generate_long_dns_query())

    # Test case: DNS response without query
    wrpcap(f"{prefix}dns_response_without_query.pcap", generate_dns_response_without_query())

    # Test case: DNS response with reused transaction ID
    wrpcap(f"{prefix}dns_response_reused_id.pcap", generate_dns_response_reused_id())

    # Test case: DNS query for tunneling (same domain)
    wrpcap(f"{prefix}dns_query_tunneling.pcap", generate_dns_query_for_tunneling())

    # Test case: DNS query and response from the same IP
    wrpcap(f"{prefix}dns_query_response_same_ip.pcap", generate_dns_query_and_response_from_the_same_ip())

    # Test case: mDNS packet not authoritative
    wrpcap(f"{prefix}not_valid_mdns.pcap", generate_mdns_packet_not_authoritative())

    # Test case: DNS query not on port 53
    wrpcap(f"{prefix}dns_query_not_on_port_53.pcap", generate_dns_query_not_on_port_53())

    # Test case: DNS not standard query
    wrpcap(f"{prefix}dns_not_standard_query.pcap", generate_dns_not_standard_query())

    # Test case: DNS suspicious number of queries
    wrpcap(f"{prefix}dns_suspicious_number_of_queries.pcap", generate_dns_suspicious_number_of_queries())

    # Test case: DNS suspicious number of answers
    wrpcap(f"{prefix}dns_suspicious_number_of_answers.pcap", generate_dns_suspicious_number_of_answers())


def generate_dhcp_non_standard_port():
    return IP(dst="255.255.255.255") / UDP(sport=random.randint(1000, 2000), dport=random.randint(1000, 2000)) / BOOTP(
        xid=0x12345678) / DHCP(
        options=[("message-type", 1), "end"])


def generate_dhcp_no_message_type():
    return IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678) / DHCP(options=["end"])


def generate_dhcp_no_end_option():
    return IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678) / DHCP(
        options=[("message-type", 9), "end"])


def generate_dhcp_transaction_id_reuse():
    packets = [IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678) / DHCP(
        options=[("message-type", 1), "end"]),
               IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678) / DHCP(
                   options=[("message-type", 2), "end"])]
    return packets


def generate_dhcp_invalid_hardware_address_length():
    return IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678, hlen=5) / DHCP(
        options=[("message-type", 1), "end"])


def generate_dhcp_invalid_broadcast_flag():
    return IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678, flags=0x1234) / DHCP(
        options=[("message-type", 1), "end"])


def generate_dhcp_no_server_identifier():
    return IP(dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(xid=0x12345678) / DHCP(
        options=[("message-type", 5), "end"])


def generate_dhcp_no_requested_ip():
    return IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(xid=0x12345678) / DHCP(
        options=[("message-type", 3), "end"])


def generate_dhcp_pcap(prefix):
    # Test case: DHCP packet on non-standard port
    wrpcap(f"{prefix}dhcp_non_standard_port.pcap", generate_dhcp_non_standard_port())

    # Test case: DHCP packet without message type
    wrpcap(f"{prefix}dhcp_no_message_type.pcap", generate_dhcp_no_message_type())

    # Test case: DHCP packet without end option
    wrpcap(f"{prefix}dhcp_no_end_option.pcap", generate_dhcp_no_end_option())

    # Test case: DHCP packet with reused transaction ID
    wrpcap(f"{prefix}dhcp_transaction_id_reuse.pcap", generate_dhcp_transaction_id_reuse())

    # Test case: DHCP packet with invalid hardware address length
    wrpcap(f"{prefix}dhcp_invalid_hardware_address_length.pcap", generate_dhcp_invalid_hardware_address_length())

    # Test case: DHCP packet with invalid broadcast flag
    wrpcap(f"{prefix}dhcp_invalid_broadcast_flag.pcap", generate_dhcp_invalid_broadcast_flag())

    # Test case: DHCP packet with suspicious options
    wrpcap(f"{prefix}dhcp_no_server_identifier.pcap", generate_dhcp_no_server_identifier())

    # Test case: DHCP packet with no requested ip
    wrpcap(f"{prefix}dhcp_no_requested_ip.pcap", generate_dhcp_no_requested_ip())


def generate_http_pcap(prefix):
    # Case 1: IP not in resolved IPs
    packet1 = IP(src="192.168.1.100", dst="10.0.0.5") / TCP(sport=1234, dport=80) / HTTP(HTTPRequest(Method=b"GET",
                                                                                                     Host=b"example.com",
                                                                                                     Path=b"/").build())
    wrpcap(f"{prefix}http_ip_not_resolved.pcap", [packet1])

    # Case 2: Non-standard port
    packet2 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=8080) / HTTP(HTTPRequest(Method=b"GET",
                                                                                                          Host=b"example.com",
                                                                                                          Path=b"/").build())
    wrpcap(f"{prefix}http_non_standard_port.pcap", [packet2])

    # Case 3: Missing Method or Host in HTTP Request
    packet3 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=80) / HTTP(
        HTTPRequest(Path=b"/").build())
    wrpcap(f"{prefix}http_missing_method_host.pcap", [packet3])

    # Case 4: Unusual HTTP Method
    packet4 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=80) / HTTP(
        HTTPRequest(Method=b"CONNECT",
                    Host=b"example.com",
                    Path=b"/").build())
    wrpcap(f"{prefix}http_unusual_method.pcap", [packet4])

    # Case 5: Overly long URL
    long_path = b"/" + b"a" * 2001
    packet5 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=80) / HTTP(HTTPRequest(Method=b"GET",
                                                                                                        Host=b"example.com",
                                                                                                        Path=long_path).build())
    wrpcap(f"{prefix}http_long_url.pcap", [packet5])

    # Case 6: Missing User-Agent Header
    packet6 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=80) / Raw(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    wrpcap(f"{prefix}http_missing_user_agent.pcap", [packet6])

    # Case 7: Overly long HTTP Response
    long_response = Raw(b"A" * 2001)
    packet7 = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=1234) / HTTP(long_response.build())
    wrpcap(f"{prefix}http_long_response.pcap", [packet7])


def generate_mac_pcap(prefix):
    # Generate multiple ARP Requests and Replies
    # Let's generate ARP replies with different MACs for the same IP (for ARP spoofing)
    arp_replies = []

    # ARP requests (for IP resolution)
    arp_requests = []
    for ip in ["192.168.1.1", "192.168.1.2", "192.168.1.3"]:
        request = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc="00:11:22:33:44:55", psrc="0.0.0.0", hwdst="ff:ff:ff:ff:ff:ff", pdst=ip
        )
        arp_requests.append(request)

    # ARP replies (with different MACs for the same IP, simulating ARP spoofing)
    arp_replies.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"
    ))

    arp_replies.append(Ether(src="00:11:22:33:44:66", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="00:11:22:33:44:66", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"
    ))

    arp_replies.append(Ether(src="00:11:22:33:44:77", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="00:11:22:33:44:77", psrc="192.168.1.2", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.2"
    ))

    # Simulate Ethernet packets with mismatched IP-MAC addresses
    eth_packets = []

    # Packet with correct MAC address for the IP
    eth_packets.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(
        src="192.168.1.1", dst="192.168.1.2"
    ))

    # Packet with mismatched MAC address for the IP (simulates IP-MAC mismatch detection)
    eth_packets.append(Ether(src="00:11:22:33:44:66", dst="ff:ff:ff:ff:ff:ff") / IP(
        src="192.168.1.1", dst="192.168.1.2"
    ))

    # Packet with another mismatched MAC address
    eth_packets.append(Ether(src="00:11:22:33:44:77", dst="ff:ff:ff:ff:ff:ff") / IP(
        src="192.168.1.2", dst="192.168.1.2"
    ))

    # Combine all packets
    all_packets = arp_requests + arp_replies + eth_packets

    # Write the packets to a pcap file
    wrpcap(f"{prefix}mac_abnormalities_extended.pcap", all_packets)


def generate_folders():
    if not os.path.exists("./pcaps"):
        os.makedirs("./pcaps")
    folders = ["./pcaps/TCP", "./pcaps/POP3", "./pcaps/IMAP", "./pcaps/SMB", "./pcaps/FTP", "./pcaps/SSH",
               "./pcaps/DNS", "./pcaps/DHCP", "./pcaps/HTTP", "./pcaps/MAC"]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)


if __name__ == "__main__":
    generate_folders()
    generate_tcp_pcap("./pcaps/TCP/tcp_anomaly_test.pcap")
    generate_pop3_pcaps("./pcaps/POP3/")
    generate_imap_pcaps("./pcaps/IMAP/")
    generate_smb_pcaps("./pcaps/SMB/")
    generate_ftp_pcap("./pcaps/FTP/")
    generate_ssh_pcap("./pcaps/SSH/")
    generate_dns_pcap("./pcaps/DNS/")
    generate_dhcp_pcap("./pcaps/DHCP/")
    generate_http_pcap("./pcaps/HTTP/")
    generate_mac_pcap("./pcaps/MAC/")
