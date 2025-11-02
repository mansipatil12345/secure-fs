"""
src/utils.py - Utility Functions

Common utility functions for the secure filesystem.
"""

import os
import time
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict, Any
import mimetypes


def detect_mime_type(file_path: Path) -> str:
    """
    Detect MIME type of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        MIME type string
    """
    mime_type, _ = mimetypes.guess_type(str(file_path))
    return mime_type or "application/octet-stream"


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count as human-readable string.
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"


def secure_random_string(length: int = 32) -> str:
    """
    Generate cryptographically secure random string.
    
    Args:
        length: Length of string
        
    Returns:
        Random hex string
    """
    return secrets.token_hex(length // 2)


def timing_safe_compare(a: bytes, b: bytes) -> bool:
    """
    Timing-safe comparison of two byte strings.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


class FileValidator:
    """
    Validator for file operations.
    """
    
    @staticmethod
    def validate_path(path: str) -> bool:
        """
        Validate file path for security.
        
        Args:
            path: File path to validate
            
        Returns:
            True if path is safe
        """
        # Normalize path
        normalized = os.path.normpath(path)
        
        # Check for path traversal attempts
        if '..' in normalized or normalized.startswith('/'):
            return False
        
        # Check for null bytes
        if '\x00' in path:
            return False
        
        # Check length
        if len(path) > 4096:  # Reasonable path length limit
            return False
        
        return True


if __name__ == "__main__":
    print("🔧 Utility Functions Demo")
    print("✅ Utility functions loaded successfully!")
