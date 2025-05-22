#!/usr/bin/env python3
"""Module that provides functions to hash and validate passwords.
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """Hashes a password with a randomly-generated salt using bcrypt.
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt)

def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a password against a given hashed password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
