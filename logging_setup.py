import logging
import os
from logging.handlers import RotatingFileHandler
from os import mkdir

# Create a directory for logs if it doesn't exist
if not os.path.exists("logs"):
    mkdir("logs")

# Set up a rotating file handler for logs
file_handler = RotatingFileHandler(
    "./logs/Network Analysis.log", maxBytes=5 * 1024 * 1024, backupCount=3  # Rotate after 5MB, keep 3 backups
)

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[file_handler]
)


def get_logger(name):
    return logging.getLogger(name)


def mkdir(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
