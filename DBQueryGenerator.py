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
    def DatabaseHandler(db: FlowAbnormalityDB):
        while True:
            try:
                print("\nMenu:")
                print("1. See total statistics")
                print("2. Do your own query")
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
