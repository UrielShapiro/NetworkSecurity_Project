import sqlite3

from scapy.config import conf

import FlowAbnormality


# Database Handler
class FlowAbnormalityDB:
    db_name = "IDS_DB"

    def __init__(self, database_name=db_name):
        # Ensure the database file is created in a 'db' folder within the project
        self.connection = sqlite3.connect(database_name)
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # First, drop the table if it exists
        self.cursor.execute("DROP TABLE IF EXISTS flow_abnormalities")
        # Create a table for FlowAbnormality
        self.cursor.execute("""
            CREATE TABLE flow_abnormalities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                abnormality_type TEXT NOT NULL,
                description TEXT NOT NULL,
                level TEXT NOT NULL
            )
        """)
        self.connection.commit()

    def insert_abnormality(self, src, dst, src_port, dst_port, protocol: int, abnormality: FlowAbnormality):
        # Insert a FlowAbnormality object into the table
        protocols = conf.protocols
        try:
            protocol = protocols[protocol].upper()
        except KeyError:
            protocol = "Unknown"

        abnormality.level = abnormality.level.name if not "_" in abnormality.level.name else abnormality.level.name.replace(
            "_", " ")   # Convert the level to a human-readable format (Remove underscores and capitalize)
        abnormality.level = abnormality.level.title()  # Capitalize the first letter of each word

        self.cursor.execute("""
            INSERT INTO flow_abnormalities (src, dst, src_port, dst_port, protocol,abnormality_type, description, level)
            VALUES (?,?,?,?,?, ?, ?, ?)
        """, (src, dst, src_port, dst_port, protocol,
              abnormality.abnormality_type, abnormality.description, abnormality.level))
        self.connection.commit()

    def get_total_statistics(self):
        # Query to get count of each abnormality_type and level
        self.cursor.execute("""
            SELECT abnormality_type, level, COUNT(*)
            FROM flow_abnormalities
            GROUP BY abnormality_type, level
        """)
        results = self.cursor.fetchall()
        return results

    def get_distinct_sources(self):
        # Query to get distinct source addresses
        self.cursor.execute("SELECT DISTINCT src FROM flow_abnormalities")
        results = self.cursor.fetchall()
        return [row[0] for row in results]

    def execute_custom_query(self, query, params=None):
        # Generic method to execute a custom query
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            results = self.cursor.fetchall()
            return results
        except sqlite3.Error as e:
            return f"Error executing query: {e}"

    def close(self):
        # Close the database connection
        self.connection.close()
