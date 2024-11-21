import os
import sqlite3
import logging
from logging.handlers import RotatingFileHandler

from scapy.config import conf

import FlowAbnormality
import logging_setup


# Database Handler
class FlowAbnormalityDB:

    db_name = "IDS_DB"

    def __init__(self, database_name=db_name):
        # Ensure the database file is created in a 'db' folder within the project
        self.logger = self.setup_logger()
        self.logger.info("Initializing FlowAbnormalityDB")

        self.connection = sqlite3.connect(database_name)
        self.logger.info(f"Connected to database: {database_name}")

        self.cursor = self.connection.cursor()
        self.create_table()
        self.logger.info("Created table")

    def setup_logger(self):
        """Sets up a logger for the class."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Set the logging level

        # Ensure the logs directory exists
        log_dir = "./logs"
        logging_setup.mkdir(log_dir)

        # Create a rotating file handler
        log_file = os.path.join(log_dir, "SQL Server.log")
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

    def insert_abnormality(self, src, dst,  src_port, dst_port, protocol: int, abnormality: FlowAbnormality) -> None:
        # Insert a FlowAbnormality object into the table
        if src_port is None:
            src_port = 0
        if dst_port is None:
            dst_port = 0

        protocols = conf.protocols
        try:
            protocol = protocols[protocol].upper()
        except KeyError:
            protocol = "Unknown"
            self.logger.warning(f"Unknown protocol number: {protocol}")

        abnormality.level = abnormality.get_level() if not "_" in abnormality.get_level() else abnormality.level.name.replace(
            "_", " ")  # Convert the level to a human-readable format (Remove underscores and capitalize)
        abnormality.level = abnormality.level.title()  # Capitalize the first letter of each word

        self.cursor.execute("""
            INSERT INTO flow_abnormalities (src, dst, src_port, dst_port, protocol,abnormality_type, description, level)
            VALUES (?,?,?,?,?, ?, ?, ?)
        """, (src, dst, src_port, dst_port, protocol,
              abnormality.abnormality_type, abnormality.description, abnormality.level))
        self.connection.commit()
        self.logger.info(f"Inserted abnormality: {abnormality}")

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
                self.logger.info(f"Executed query: {query} with parameters: {params}")
            else:
                self.cursor.execute(query)
                self.logger.info(f"Executed query: {query} with no parameters")
            results = self.cursor.fetchall()
            return results
        except sqlite3.Error as e:
            self.logger.error(f"Error executing query: {e}")
            return f"Error executing query: {e}"

    def close(self):
        # Close the database connection
        self.connection.close()
        self.logger.info("Closed database connection")
