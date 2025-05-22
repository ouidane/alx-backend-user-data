#!/usr/bin/env python3
"""
Module for filtering and logging user data with PII redaction
"""

import re
import logging
import os
import mysql.connector
from typing import List
from mysql.connector.connection import MySQLConnection


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """Obfuscate values of specified fields in a log message"""
    return re.sub(
        f"({'|'.join(fields)})=.+?{separator}",
        lambda m: f"{m.group(1)}={redaction}{separator}",
        message
    )


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class for logging"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return filter_datum(self.fields, self.REDACTION, original, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Creates and returns a configured logger for user data"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(list(PII_FIELDS))
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def get_db() -> MySQLConnection:
    """Establishes and returns a secure database connection"""
    return mysql.connector.connect(
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME")
    )


def main() -> None:
    """Main function to retrieve and log user data with redacted PII fields"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        row_str = "; ".join(f"{k}={v}" for k, v in row.items()) + ";"
        logger.info(row_str)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
