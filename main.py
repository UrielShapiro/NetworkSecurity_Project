import queue
from pathlib import Path
import threading
from scapy.interfaces import  ifaces
from PacketSniffer import sniff_packets, read_pcap

# ANSI color codes for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"  # Reset to default color

class IDS:
    def __init__(self, sniff: bool, sniff_interface:str, pcap_path: str = None):
        self.packet_flow = dict()
        self.snifferFlag = sniff
        self.__resolvedIPs = {}
        self.__running = False
        self.__sniffing_thread = None
        self.packet_arr = queue.Queue()
        self.cond = threading.Condition()

        if sniff:
            self.interface = sniff_interface
        else:
            self.path = pcap_path

    def start(self):
        self.__running = True
        if self.snifferFlag:
            self.__sniffing_thread = threading.Thread(target=self.sniff_packets)
            self.__sniffing_thread.start()
        else:
            self.read_pcap()

    def is_running(self):
        return self.__running == True

    def get_cond(self):
        return self.cond

    def stop(self):
        self.__running = False
        if self.snifferFlag:
            self.__sniffing_thread.join()

    def sniff_packets(self):
        while self.__running:
            packet = sniff_packets(self.interface)
            self.packet_arr.put(packet)

    def read_pcap(self):
        self.packet_arr.put(read_pcap(self.path))

def main(sniff_flag: bool, sniff_interface: str = None, pcap_path: str = None):
    ids = IDS(sniff_flag, sniff_interface, pcap_path)
    ids.start()
    while ids.is_running():
        p = ids.packet_arr.get()
        for a in p:
            a.show()

    ids.stop()
    # while ids.is_running():
    #     if ids.snifferFlag:
    #         packet = sniff_packets(sys.argv[2])
    #     else:
    #         packet = read_pcap(sys.argv[1])
    # try:
    #     packets = rdpcap(argv)
    #     flow = dict()
    #     for packet in packets:
    #         five_tuple = PacketAnalyzer.export_to_five_tuple(packet)
    #         if five_tuple in flow:
    #             flow[five_tuple].update_packet(packet)
    #         else:
    #             flow[five_tuple] = PacketFlow(packet)
    # except Exception as e:
    #     print(f"An error occurred: {e}")
    #     sys.exit(1)




if __name__ == "__main__":

    print("Would you like to sniff packets or read from a pcap file?")
    print("1. Sniff packets")
    print("2. Read packets from a pcap file")
    sniffing = input("Enter your choice as an integer: ") == "1"

    if sniffing:
        '''
        This block of code will only work on windows machines due to the use of iface.
        '''
        print("Available interfaces:")
        interface_map = {}
        for idx, iface in enumerate(ifaces.values()):
            interface_name = iface.dev if hasattr(iface, 'dev') else iface.name
            interface_desc = iface.description if hasattr(iface, 'description') else "Unknown description"
            print(f"{idx}: {interface_desc} ({interface_name})")
            interface_map[idx] = interface_name

        # Prompt the user to select an interface by number
        choice = int(input("Select the interface by number: "))
        interface = interface_map[choice]
        main(True, interface)

    else: # Read from a pcap file
        while True:
            path = input("Enter the path to the pcap file: ")
            if not path.endswith(".pcap"):
                print(f"{RED}Only .pcap files are supported.{RESET}")
                continue
            file_path = Path(path)
            if not file_path.is_file():
                print(f"{RED}The file provided does not exist.{RESET}")
            else:
                break
        main(False, None, path)