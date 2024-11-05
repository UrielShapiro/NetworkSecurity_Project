import queue
from pathlib import Path
from threading import Condition, Thread
from scapy.interfaces import  ifaces

import PacketAnalyzer
import FlowAnalyzer
import PacketSniffer

# ANSI color codes for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"  # Reset to default color

class IDS:
    def __init__(self, sniff_flag: bool, sniff_interface:str = None, pcap_path: str = None):
        self.packet_flow = dict()
        self.snifferFlag = sniff_flag
        self.__resolvedIPs = {}
        self.__running = False
        self.__sniffing_thread = None
        self.__packet_analyzer_thread = None
        self.packet_arr = queue.Queue()
        self.cond = Condition()
        self.reading_done = False
        self.analyzing_done = False

        if sniff_flag:
            self.interface = sniff_interface
        else:
            self.path = pcap_path

    def start(self):
        self.__running = True
        self.__packet_analyzer_thread = Thread(target=self.analyze_packet)
        self.__packet_analyzer_thread.start()
        if self.snifferFlag:
            self.__sniffing_thread = Thread(target=self.sniff_packets)
            self.__sniffing_thread.start()
        else:
            self.__sniffing_thread = Thread(target=self.read_pcap)
            self.__sniffing_thread.start()

    def is_running(self):
        return self.__running == True

    def stop(self):
        self.__running = False
        with self.cond:
            self.cond.notify_all() # Ensure any waiting threads are notified
        self.__sniffing_thread.join()
        self.__packet_analyzer_thread.join()

    def sniff_packets(self):
        while self.is_running():
            packet = PacketSniffer.sniff_packets(self.interface)
            with self.cond:
                self.packet_arr.put(packet)
                self.cond.notify()

    def read_pcap(self):
        for p in PacketSniffer.read_pcap(self.path):
            with self.cond:
                self.packet_arr.put(p)
                self.cond.notify()

            with self.cond:
                self.reading_done = True
                self.cond.notify_all() # Notify all waiting threads that reading is done

    def analyze_packet(self):
        while self.is_running():
            if not self.snifferFlag:
                with self.cond:
                    while self.packet_arr.empty() and not self.reading_done:
                        self.cond.wait()  # Wait for new packets or reading to complete

                        if self.packet_arr.empty() and self.reading_done:
                            break # Break out of the loop if no more packets are available and reading is done

            packet = self.packet_arr.get()

            five_tuple = PacketAnalyzer.PacketAnalyzer(packet)
            if five_tuple in self.packet_flow:
                self.packet_flow[five_tuple].update_packet(packet)
            else:
                self.packet_flow[five_tuple] = FlowAnalyzer.FlowAnalyzer(packet)

            if not self.snifferFlag:
                with self.cond:
                    self.analyzing_done = True
                    self.cond.notify_all()  # Notify main thread that analysis is complete

def main(sniff_flag: bool, sniff_interface: str = None, pcap_path: str = None):
    ids = IDS(sniff_flag, sniff_interface, pcap_path)
    ids.start()
    while ids.is_running():
        with ids.cond:
            if not ids.snifferFlag: # If reading from a pcap file, wait for reading and analyzing to complete
                if not ids.reading_done or not ids.analyzing_done:
                    ids.cond.wait()
                if ids.reading_done and ids.analyzing_done:
                    break

        while True:
            stop = input("Would you like to stop the IDS? (y/n): ")
            if stop.lower() == "y":
                break
        break
    ids.stop()

    # while ids.is_running():
    #     p = ids.packet_arr.get()
    #     for a in p:
    #         a.show()
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
    sniffing = int(input("Enter your choice as an integer: ")) == 1

    if sniffing:
        '''
        This block of code will only work on windows machines due to the use of iface.
        '''
        print("Available interfaces:")
        interfaces_map = {}
        for index, iface in enumerate(ifaces.values()):
            interface_name = iface.dev if hasattr(iface, 'dev') else iface.name
            interface_desc = iface.description if hasattr(iface, 'description') else "Unknown description"
            print(f"{index}: {interface_desc} ({interface_name})")
            interfaces_map[index] = interface_name

        # Prompt the user to select an interface by number
        while True:
            choice = int(input("Select the interface by number: "))
            if choice not in interfaces_map.keys():
                print(f"{RED}Invalid choice. Available values are: ({', '.join(str(key) for key in interfaces_map.keys())}){RESET}")
                continue
            break
        interface = interfaces_map[choice]
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
                print(f"{GREEN}File found!{RESET}")
                break
        main(False, None, path)