import logging
import os
import queue
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Condition, Thread

from scapy.interfaces import ifaces

import FlowAnalyzer
import PacketSniffer
import logging_setup
from DBQueryGenerator import *
from FlowAnalyzer import FlowAnalyzer
from SQL_Server import FlowAbnormalityDB

# ANSI color codes for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"  # Reset to default color


class IDS:
    def __init__(self, sniff_flag: bool, sniff_interface: str = None, pcap_path: str = None):
        self.snifferFlag = sniff_flag
        self.__running = False
        self.__sniffing_thread = None
        self.__packet_analyzer_thread = None
        self.packet_queue = queue.Queue()  # Queue to store packets
        self.cond = Condition()  # Condition variable to synchronize threads
        self.reading_done = False
        self.analyzing_done = False
        self.flow_analyzer = FlowAnalyzer()
        self.db = FlowAbnormalityDB()
        self.logger = self.setup_logger()

        if sniff_flag:
            self.interface = sniff_interface
            self.logger.info(f"Initializing IDS with interface: {sniff_interface}")
        else:
            self.path = pcap_path
            self.logger.info(f"Initializing IDS with pcap file: {pcap_path}")
        self.logger.info("Initializing IDS")


    def start(self):
        self.logger.info("Starting IDS")
        self.__running = True
        self.__packet_analyzer_thread = Thread(target=self.analyze_packet)
        self.__packet_analyzer_thread.start()
        if self.snifferFlag:
            self.__sniffing_thread = Thread(target=self.sniff_packets)
            self.__sniffing_thread.start()
        else:
            self.__sniffing_thread = Thread(target=self.read_pcap)
            self.__sniffing_thread.start()
        self.logger.info("All IDS threads started")

    def is_running(self):
        return self.__running

    def stop(self):
        self.logger.info("Stopping IDS")
        self.__running = False
        with self.cond:
            self.cond.notify_all()  # Ensure any waiting threads are notified
            self.logger.info("Notified all waiting threads")
        self.__sniffing_thread.join()
        self.__packet_analyzer_thread.join()
        self.logger.info("All IDS threads stopped")
        for five_tuple, abnormality in self.flow_analyzer.get_abnormalities():
            src = five_tuple[0]
            dst = five_tuple[1]
            src_port = five_tuple[2]
            dst_port = five_tuple[3]
            protocol = five_tuple[4]
            self.db.insert_abnormality(src=src, dst=dst, src_port=src_port, dst_port=dst_port,
                                       protocol=protocol, abnormality=abnormality)
        self.logger.info("Inserted all abnormalities into the database")
        self.flow_analyzer.print()  # TODO: Remove from final code
        self.logger.info("User is now prompted using the database_handler method")
        DBQueryGenerator.database_handler(self.db)
        self.logger.info("Database handler completed, IDS stopped")

    def sniff_packets(self):
        while self.is_running():
            packet = PacketSniffer.sniff_packets(self.interface)
            with self.cond:
                self.packet_queue.put(packet)
                self.cond.notify()
                self.logger.debug(f"Packet added to the queue: {packet.summary()}, waking up the analyzer")
                self.logger.debug(f"Packet queue size: {self.packet_queue.qsize()}")

    def read_pcap(self):
        for p in PacketSniffer.read_pcap(self.path):
            with self.cond:
                self.packet_queue.put(p)
                self.cond.notify()
                self.logger.debug(f"Packet added to the queue: {p.summary()}, waking up the analyzer")
                self.logger.debug(f"Packet queue size: {self.packet_queue.qsize()}")

        with self.cond:
            self.reading_done = True
            self.cond.notify_all()  # Notify all waiting threads that reading is done
            self.logger.info("Reading from pcap file is done")

    def analyze_packet(self):
        while self.is_running():
            if not self.snifferFlag:
                with self.cond:
                    while self.packet_queue.empty() and not self.reading_done:
                        self.cond.wait()  # Wait for new num_of_packets or reading to complete

                    if self.packet_queue.empty() and self.reading_done:
                        break  # Break out if reading is done and queue is empty

            try:
                packet = self.packet_queue.get(timeout=1)  # Add timeout to avoid indefinite blocking
            except queue.Empty:
                self.logger.debug("Packet queue is empty")
                continue  # Skip to the next iteration if the queue is empty

            # Process packet
            if packet in self.flow_analyzer:
                self.flow_analyzer.update_packet(packet)
            else:
                self.flow_analyzer.add_packet(packet)

            # Notify the main thread that analysis is complete
        with self.cond:
            self.analyzing_done = True
            self.cond.notify_all()
            self.logger.info("Analyzing packets is done")

    def __del__(self):
        self.db.close()
        self.logger.info("Closed the database connection")

    def setup_logger(self):
        """Sets up a logger for the class."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Set the logging level

        # Ensure the logs directory exists
        log_dir = "./logs"
        logging_setup.mkdir(log_dir)

        # Create a rotating file handler
        log_file = os.path.join(log_dir, "IDS.log")
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5
        )
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)

        # Add the handler to the logger
        self.logger.addHandler(file_handler)
        return self.logger


def main(sniff_flag: bool, sniff_interface: str = None, pcap_path: str = None):
    ids = IDS(sniff_flag, sniff_interface, pcap_path)
    ids.start()
    while ids.is_running():
        with ids.cond:
            if not ids.snifferFlag:  # If reading from a pcap file, wait for reading and analyzing to complete
                if not ids.reading_done or not ids.analyzing_done:
                    ids.cond.wait()
                if ids.reading_done and ids.analyzing_done:
                    break

        end = False  # Flag to end the outer loop
        while ids.snifferFlag:
            print(f"\n{GREEN}Analyzing packets...{RESET}")
            stop = input("Would you like to stop the IDS? (y/n): ")
            if stop.lower() == "y":
                end = True
                break
        if end:
            break

    ids.stop()


if __name__ == "__main__":
    print(f"{BLUE}Welcome to the Intrusion Detection System!{RESET}", end="\n\n")

    sniffing = False
    while True:
        print(f"Would you like to {YELLOW}sniff packets{RESET} or read from a {YELLOW}pcap file{RESET}?")
        print("1. Sniff packets")
        print("2. Read packets from a pcap file")
        answer = input("Enter your choice as an integer: ")
        try:
            answer = int(answer)
        except ValueError:
            print(f"{RED}Invalid choice!{RESET}")
            continue
        if not answer == 1 and not answer == 2:
            print(f"{RED}Invalid choice!{RESET}")
            continue
        else:
            sniffing = answer == 1
            break

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
        while True and sniffing:
            choice = int(input("Select the interface by number: "))
            if choice not in interfaces_map.keys():
                print(
                    f"{RED}Invalid choice. Available values are: ({', '.join(str(key) for key in interfaces_map.keys())}){RESET}")
                continue
            break
        interface = interfaces_map[choice]
        main(True, interface)

    else:  # Read from a pcap file
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
