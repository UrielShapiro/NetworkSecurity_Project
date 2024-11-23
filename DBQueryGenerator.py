from abc import ABC

from SQL_Server import FlowAbnormalityDB

# ANSI color codes for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"  # Reset to default color


class DBQueryGenerator(ABC):
    @staticmethod
    def database_handler(db: FlowAbnormalityDB) -> None:
        """
        This method is used to handle the user prompt and do the required db operations.
        :param db: FlowAbnormalityDB object
        :return: None
        """
        while True:
            try:
                print("\nMenu:")
                print("1. See total statistics")
                print("2. Other query options")
                print("3. Exit")

                choice = int(input("Enter your choice: "))
                if choice == 1:
                    DBQueryGenerator.process_statistics(db)
                elif choice == 2:
                    DBQueryGenerator.process_custom_query(db)
                elif choice == 3:
                    print(f"{RED}Exiting...{RESET}")
                    break
                else:
                    print(f"\n{RED}Invalid choice!{RESET}")
            except KeyboardInterrupt:
                print("\nExiting...")
            except ValueError:
                print(f"\n{RED}Invalid choice!{RESET}")

    @staticmethod
    def process_statistics(db: FlowAbnormalityDB):
        stats = db.get_total_statistics()
        if not stats:
            print(f"\n{GREEN}No statistics found in the database.{RESET}")
            return
        print("\nTotal Statistics:")
        for abnormality_type, level, count in stats:
            print(f"{RED}{abnormality_type}{RESET}\tLevel: {YELLOW}{level}{RESET}, Count: {count}")

    @staticmethod
    def process_custom_query(db: FlowAbnormalityDB):
        while True:
            print("\nQuery Options:")
            print("1. Get records by source address")
            print("2. Get records by abnormality type")
            print("3. Exit")

            choice = int(input("Enter your choice: "))
            if choice == 1:
                DBQueryGenerator.get_by_source(db)
            elif choice == 2:
                DBQueryGenerator.get_by_abnormality(db)
            elif choice == 3:
                print(f"{RED}Exiting...{RESET}")
                break
            else:
                print(f"\n{RED}Invalid choice!{RESET}")



    @staticmethod
    def get_by_abnormality(db: FlowAbnormalityDB) -> None:
        # Retrieve all distinct AbnormalityType values
        abnormality_types = db.get_all_abnormality_types()
        if not abnormality_types:
            print(f"\n{GREEN}No abnormality types found in the database.{RESET}")
            return

        # Display distinct AbnormalityType values
        print("\nDistinct Abnormality Types:")
        for idx, ab_type in enumerate(abnormality_types, start=1):
            print(f"{idx}. {ab_type}")

        # Get user's choice
        while True:
            choice = int(input("Select the abnormality type (enter the number): "))
            if choice < 1 or choice > len(abnormality_types):
                print(f"{RED}Invalid selection!{RESET}")
                continue
            break

        selected_type = abnormality_types[choice - 1]

        # Query and display all records with the selected AbnormalityType
        query = "SELECT * FROM flow_abnormalities WHERE abnormality_type = ?"
        results = db.execute_custom_query(query, (selected_type,))
        print(f"\nRecords for abnormality type {selected_type}:")
        for record in results:
            print(record)

    @classmethod
    def get_by_source(cls, db: FlowAbnormalityDB) -> None:
        sources = db.get_distinct_sources()
        if not sources:
            print(f"\n{GREEN}No sources found in the database.{RESET}")
            return

        # Display distinct source addresses
        print("\nDistinct Source Addresses:")
        for idx, src in enumerate(sources, start=1):
            print(f"{idx}. {src}")

        # Get user's choice
        choice = int(input("Select the source address (enter the number): "))
        if choice < 1 or choice > len(sources):
            print(f"{RED}Invalid selection!{RESET}")
            return

        selected_src = sources[choice - 1]

        # Get query type
        print("\nSelect query type:")
        print("1. Count all records for this source")
        print("2. View all records for this source")
        query_type = int(input("Enter your choice: "))

        if query_type == 1:
            query = "SELECT COUNT(*) FROM flow_abnormalities WHERE src = ?"
            results = db.execute_custom_query(query, (selected_src,))
            print(f"\n{GREEN}Count of records for source {selected_src}: {results[0][0]}{RESET}")
        elif query_type == 2:
            query = "SELECT * FROM flow_abnormalities WHERE src = ?"
            results = db.execute_custom_query(query, (selected_src,))
            print(f"Records for source {selected_src}:")
            for record in results:
                print(record)
        else:
            print("Invalid query type!")
