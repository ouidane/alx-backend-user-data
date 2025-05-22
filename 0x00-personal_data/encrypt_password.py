#!/usr/bin/env python3
"""
Module that provides functions to hash and validate passwords using bcrypt.
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hashes a password with a randomly-generated salt using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a given hashed password.

    Args:
        hashed_password (bytes): The previously hashed password.
        password (str): The plain text password to validate.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
