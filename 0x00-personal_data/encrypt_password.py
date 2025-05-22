#!/usr/bin/env python3
"""Module that provides functions to hash and validate passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password with a randomly-generated salt using bcrypt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a password against a given hashed password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
