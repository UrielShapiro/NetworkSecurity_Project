from scapy.all import *
import random

from scapy.layers.inet import IP, TCP


def create_tcp_packet(ip_src, ip_dst, sport, dport, flags):
    """Helper function to create TCP packets."""
    ip = IP(src=ip_src, dst=ip_dst)
    tcp = TCP(sport=sport, dport=dport, flags=flags)
    return ip / tcp

def generate_pcap(file_name):
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

def generate_pop3_pcaps():
    # Create multiple packets for POP3 Authentication Failure (incorrect USER/PASS)
    failure_data = "USER testuser\r\nPASS incorrectpassword\r\nincorrect login"
    auth_fail_packets = []
    for i in range(500):
        auth_fail_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, failure_data))
    wrpcap("../pcaps/POP3/pop3_authentication_failure.pcap", auth_fail_packets)

    # Create multiple packets for POP3 Data Exfiltration (RETR command)
    retr_data = "RETR 1\r\n"
    retr_packets = []
    for i in range(100):
        retr_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, retr_data))
    wrpcap("../pcaps/POP3/pop3_data_exfiltration.pcap", retr_packets)

    # Create multiple failed authentication attempts for brute force simulation
    brute_force_data = "USER testuser\r\nPASS incorrectpassword\r\nincorrect login"
    brute_force_packets = []
    for i in range(500):
        brute_force_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, brute_force_data))
    wrpcap("../pcaps/POP3/multiple_pop3_authentication_failures.pcap", brute_force_packets)

    # Create multiple RETR commands for command flooding/data exfiltration simulation
    retr_flood_data = "RETR 1\r\n"
    retr_flood_packets = []
    for i in range(100):
        retr_flood_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 110, 110, retr_flood_data))
    wrpcap("../pcaps/POP3/multiple_retr_commands.pcap", retr_flood_packets)

def generate_imap_pcaps(prefix):
    # Create multiple packets for IMAP Authentication Failure (failed LOGIN)
    login_failure_data = "LOGIN user password NO\r\n"
    auth_fail_packets = []
    for i in range(500):
        auth_fail_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 143, 143, login_failure_data))
    wrpcap(f"{prefix}imap_authentication_failure.pcap", auth_fail_packets)

    # Create multiple packets for IMAP Command Flooding (SELECT, FETCH, LOGIN commands)
    command_flood_data = ["SELECT inbox\r\n", "FETCH 1:* (FLAGS)\r\n", "LOGIN user\r\n"]
    command_flood_packets = []
    for i in range(100):
        command_flood_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 143, 143, command_flood_data[random.randint(0, 2)]))
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
    suspicious_access_data = [b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00ADMIN$", b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00C$", b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00ADMIN", b"\x00\x00\x00\x00\x00\x00\x00\x00SMB_COM_SESSION_SETUP\x00\x00IPC$"]
    suspicious_access_packets = []
    for i in range(500):
        suspicious_access_packets.append(create_pop3_imap_smb_packet("192.168.1.1", "192.168.1.2", 445, 445, suspicious_access_data[random.randint(0, 3)]))
    wrpcap(f"{prefix}smb_suspicious_access.pcap", suspicious_access_packets)

if __name__ == "__main__":
    generate_pcap("../pcaps/TCP/tcp_anomaly_test.pcap")
    generate_pop3_pcaps()
    generate_imap_pcaps("../pcaps/IMAP/")
    generate_smb_pcaps("../pcaps/SMB/")
