"""
src/secure_fs.py - FUSE Filesystem Integration

Main secure filesystem implementation with:
- Transparent encryption/decryption via FUSE
- End-to-end integrity checks
- Comprehensive audit logging
- Rate limiting and security controls
- Real-time monitoring and alerts
"""

import os
import errno
import stat
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any
import logging

try:
    from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
except ImportError:
    print("Error: fusepy not installed. Install with: pip install fusepy")
    exit(1)

from .crypto import CryptoManager
from .integrity import IntegrityChecker
from .metadata import SecureMetadataManager, FileMetadata
from .audit_logger import AuditLogger, EventType, Severity
from .rate_limiter import RateLimiter, LimitType


class SecureFileSystem(LoggingMixIn, Operations):
    """
    Production-ready secure FUSE filesystem.
    
    Features:
    - Transparent file encryption/decryption
    - Digital signatures and integrity verification
    - Comprehensive audit logging
    - Rate limiting and lockout policies
    - Real-time security monitoring
    """
    
    def __init__(self, storage_path: Path, mount_point: Path):
        """
        Initialize secure filesystem.
        
        Args:
            storage_path: Path to encrypted storage directory
            mount_point: FUSE mount point
        """
        self.storage_path = storage_path
        self.mount_point = mount_point
        
        # Ensure directories exist
        self.storage_path.mkdir(exist_ok=True)
        self.encrypted_dir = self.storage_path / "encrypted"
        self.encrypted_dir.mkdir(exist_ok=True)
        
        # Initialize security components
        self.crypto_manager = CryptoManager(self.storage_path / "master.key")
        self.integrity_checker = IntegrityChecker(self.storage_path / "integrity_keys")
        self.metadata_manager = SecureMetadataManager(
            self.storage_path / "metadata",
            self.crypto_manager,
            self.integrity_checker
        )
        self.audit_logger = AuditLogger(self.storage_path / "logs")
        self.rate_limiter = RateLimiter(self.storage_path / "rate_limiter_config.json")
        
        # File handle tracking
        self._file_handles: Dict[int, Dict[str, Any]] = {}
        self._next_fh = 1
        self._fh_lock = threading.Lock()
        
        # Statistics
        self._stats = {
            'files_created': 0,
            'files_read': 0,
            'files_written': 0,
            'files_deleted': 0,
            'integrity_failures': 0,
            'rate_limit_violations': 0
        }
        
        # Current user context (simplified for demo)
        self._current_user = "system"
        self._current_session = "default_session"
        
        # Log system startup
        self.audit_logger.log_system_event("SYSTEM_START", "Secure filesystem mounted")
        
        print(f"🔒 SecureFS initialized:")
        print(f"   Storage: {self.storage_path}")
        print(f"   Mount: {self.mount_point}")
        print(f"   Encryption: AES-256-GCM")
        print(f"   Signatures: RSA-2048")
    
    def _get_user_context(self) -> tuple:
        """Get current user context for operations."""
        # In a real implementation, this would extract user info from the FUSE context
        return self._current_user, self._current_session, "127.0.0.1"
    
    def _check_rate_limit(self, action: str, limit_type: LimitType) -> bool:
        """Check rate limit for current operation."""
        user_id, session_id, ip_address = self._get_user_context()
        
        allowed, reason, delay = self.rate_limiter.check_rate_limit(
            user_id, limit_type, action, ip_address
        )
        
        if not allowed:
            self._stats['rate_limit_violations'] += 1
            self.audit_logger.log_security_event(
                "RATE_LIMIT_EXCEEDED", "MEDIUM",
                f"Rate limit exceeded for {action}: {reason}",
                user_id, {"delay_seconds": delay}
            )
            
            if delay > 0:
                time.sleep(min(delay, 5))  # Cap delay at 5 seconds for FUSE operations
        
        # Record the attempt
        self.rate_limiter.record_attempt(
            user_id, limit_type, action, allowed, ip_address
        )
        
        return allowed
    
    def _verify_file_integrity(self, metadata: FileMetadata, file_path: Path) -> bool:
        """Verify file integrity before access."""
        try:
            # Check if encrypted file exists
            if not file_path.exists():
                return False
            
            # Verify checksum if available
            if metadata.checksum:
                current_checksum = self.integrity_checker.calculate_checksum(file_path)
                if current_checksum != metadata.checksum:
                    self._stats['integrity_failures'] += 1
                    self.audit_logger.log_security_event(
                        "INTEGRITY_FAILURE", "HIGH",
                        f"Checksum mismatch for {metadata.original_path}",
                        details={"expected": metadata.checksum, "actual": current_checksum}
                    )
                    return False
            
            # Verify signature if available
            if metadata.signature:
                signature_bytes = bytes.fromhex(metadata.signature)
                if not self.integrity_checker.verify_file_signature(file_path, signature_bytes):
                    self._stats['integrity_failures'] += 1
                    self.audit_logger.log_security_event(
                        "INTEGRITY_FAILURE", "HIGH",
                        f"Signature verification failed for {metadata.original_path}"
                    )
                    return False
            
            return True
            
        except Exception as e:
            self.audit_logger.log_security_event(
                "INTEGRITY_FAILURE", "HIGH",
                f"Integrity check error for {metadata.original_path}: {str(e)}"
            )
            return False
    
    def _update_file_integrity(self, metadata: FileMetadata, file_path: Path):
        """Update integrity information after file modification."""
        try:
            # Calculate new checksum
            checksum = self.integrity_checker.calculate_checksum(file_path)
            
            # Create new signature
            signature = self.integrity_checker.sign_file(file_path)
            
            # Update metadata
            self.metadata_manager.set_encryption_info(
                metadata.file_id,
                metadata.wrapped_key_nonce,
                metadata.wrapped_key,
                checksum,
                signature.hex()
            )
            
        except Exception as e:
            self.audit_logger.log_security_event(
                "INTEGRITY_FAILURE", "MEDIUM",
                f"Failed to update integrity info: {str(e)}"
            )
    
    def _get_encrypted_path(self, metadata: FileMetadata) -> Path:
        """Get path to encrypted file."""
        return self.encrypted_dir / metadata.encrypted_filename
    
    # FUSE Operations Implementation
    
    def getattr(self, path, fh=None):
        """Get file attributes."""
        if not self._check_rate_limit("GETATTR", LimitType.FILE_ACCESS):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            if path == '/':
                # Root directory
                st = {
                    'st_mode': stat.S_IFDIR | 0o755,
                    'st_nlink': 2,
                    'st_size': 0,
                    'st_ctime': time.time(),
                    'st_mtime': time.time(),
                    'st_atime': time.time()
                }
                return st
            
            # Get metadata for file
            metadata = self.metadata_manager.get_metadata_by_path(path)
            if not metadata:
                self.audit_logger.log_access(
                    user_id, "GETATTR", path, "NOT_FOUND", session_id, ip_address
                )
                raise FuseOSError(errno.ENOENT)
            
            # Update access time
            self.metadata_manager.update_access_time(metadata.file_id)
            
            # Return file attributes
            st = {
                'st_mode': stat.S_IFREG | int(metadata.permissions, 8),
                'st_nlink': 1,
                'st_size': metadata.file_size,
                'st_ctime': metadata.created_timestamp,
                'st_mtime': metadata.modified_timestamp,
                'st_atime': metadata.accessed_timestamp
            }
            
            self.audit_logger.log_access(
                user_id, "GETATTR", path, "SUCCESS", session_id, ip_address,
                {"file_size": metadata.file_size}
            )
            
            return st
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_access(
                user_id, "GETATTR", path, "ERROR", session_id, ip_address,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def readdir(self, path, fh):
        """List directory contents."""
        if not self._check_rate_limit("READDIR", LimitType.FILE_ACCESS):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            if path != '/':
                raise FuseOSError(errno.ENOENT)
            
            # Get list of files from metadata
            files = self.metadata_manager.list_files()
            
            # Extract filenames
            entries = ['.', '..']
            for file_info in files:
                filename = os.path.basename(file_info['path'])
                if filename:
                    entries.append(filename)
            
            self.audit_logger.log_access(
                user_id, "READDIR", path, "SUCCESS", session_id, ip_address,
                {"file_count": len(entries) - 2}
            )
            
            return entries
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_access(
                user_id, "READDIR", path, "ERROR", session_id, ip_address,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def open(self, path, flags):
        """Open file."""
        if not self._check_rate_limit("OPEN", LimitType.FILE_ACCESS):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            # Get metadata
            metadata = self.metadata_manager.get_metadata_by_path(path)
            if not metadata:
                self.audit_logger.log_access(
                    user_id, "OPEN", path, "NOT_FOUND", session_id, ip_address
                )
                raise FuseOSError(errno.ENOENT)
            
            # Verify integrity before opening
            encrypted_path = self._get_encrypted_path(metadata)
            if not self._verify_file_integrity(metadata, encrypted_path):
                self.audit_logger.log_access(
                    user_id, "OPEN", path, "INTEGRITY_FAILURE", session_id, ip_address
                )
                raise FuseOSError(errno.EIO)
            
            # Create file handle
            with self._fh_lock:
                fh = self._next_fh
                self._next_fh += 1
                
                self._file_handles[fh] = {
                    'metadata': metadata,
                    'flags': flags,
                    'path': path,
                    'encrypted_path': encrypted_path,
                    'opened_at': time.time()
                }
            
            self.audit_logger.log_access(
                user_id, "OPEN", path, "SUCCESS", session_id, ip_address,
                {"flags": flags, "file_handle": fh}
            )
            
            return fh
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_access(
                user_id, "OPEN", path, "ERROR", session_id, ip_address,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def read(self, path, size, offset, fh):
        """Read file data."""
        if not self._check_rate_limit("READ", LimitType.FILE_ACCESS):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            # Get file handle info
            if fh not in self._file_handles:
                raise FuseOSError(errno.EBADF)
            
            handle_info = self._file_handles[fh]
            metadata = handle_info['metadata']
            encrypted_path = handle_info['encrypted_path']
            
            # Verify integrity before read
            if not self._verify_file_integrity(metadata, encrypted_path):
                raise FuseOSError(errno.EIO)
            
            # Decrypt file and read data
            with open(encrypted_path, 'rb') as encrypted_file:
                # Create temporary decrypted file
                import tempfile
                with tempfile.NamedTemporaryFile() as temp_file:
                    # Decrypt entire file (in production, you'd want streaming)
                    self.crypto_manager.decrypt_file_stream(
                        encrypted_file, temp_file, path
                    )
                    
                    # Read requested data
                    temp_file.seek(offset)
                    data = temp_file.read(size)
            
            # Update access time
            self.metadata_manager.update_access_time(metadata.file_id)
            self._stats['files_read'] += 1
            
            self.audit_logger.log_access(
                user_id, "READ", path, "SUCCESS", session_id, ip_address,
                {"bytes_read": len(data), "offset": offset}
            )
            
            return data
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_access(
                user_id, "READ", path, "ERROR", session_id, ip_address,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def write(self, path, data, offset, fh):
        """Write file data."""
        if not self._check_rate_limit("WRITE", LimitType.FILE_OPERATION):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            # Get file handle info
            if fh not in self._file_handles:
                raise FuseOSError(errno.EBADF)
            
            handle_info = self._file_handles[fh]
            metadata = handle_info['metadata']
            encrypted_path = handle_info['encrypted_path']
            
            # For simplicity, we'll rewrite the entire file
            # In production, you'd want more sophisticated partial updates
            
            # Read existing data if file exists
            existing_data = b''
            if encrypted_path.exists():
                with open(encrypted_path, 'rb') as encrypted_file:
                    import tempfile
                    with tempfile.NamedTemporaryFile() as temp_file:
                        self.crypto_manager.decrypt_file_stream(
                            encrypted_file, temp_file, path
                        )
                        temp_file.seek(0)
                        existing_data = temp_file.read()
            
            # Update data at offset
            if offset > len(existing_data):
                existing_data += b'\x00' * (offset - len(existing_data))
            
            new_data = existing_data[:offset] + data + existing_data[offset + len(data):]
            
            # Encrypt and write new data
            import tempfile
            with tempfile.NamedTemporaryFile() as temp_input:
                temp_input.write(new_data)
                temp_input.seek(0)
                
                with open(encrypted_path, 'wb') as encrypted_file:
                    self.crypto_manager.encrypt_file_stream(
                        temp_input, encrypted_file, path
                    )
            
            # Update metadata
            self.metadata_manager.update_metadata(
                metadata.file_id,
                file_size=len(new_data),
                modified_timestamp=time.time()
            )
            
            # Update integrity information
            self._update_file_integrity(metadata, encrypted_path)
            self._stats['files_written'] += 1
            
            self.audit_logger.log_file_operation(
                user_id, "WRITE", path, "SUCCESS", session_id,
                {"bytes_written": len(data), "offset": offset, "new_size": len(new_data)}
            )
            
            return len(data)
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_file_operation(
                user_id, "WRITE", path, "ERROR", session_id,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def create(self, path, mode):
        """Create new file."""
        if not self._check_rate_limit("CREATE", LimitType.FILE_OPERATION):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            # Check if file already exists
            existing = self.metadata_manager.get_metadata_by_path(path)
            if existing:
                raise FuseOSError(errno.EEXIST)
            
            # Create metadata for new file
            metadata = self.metadata_manager.create_file_metadata(
                original_path=path,
                file_size=0,
                owner=user_id,
                permissions=oct(mode)[-3:],
                mime_type="application/octet-stream"
            )
            
            # Create empty encrypted file
            encrypted_path = self._get_encrypted_path(metadata)
            import tempfile
            with tempfile.NamedTemporaryFile() as temp_input:
                temp_input.write(b'')
                temp_input.seek(0)
                
                with open(encrypted_path, 'wb') as encrypted_file:
                    encryption_info = self.crypto_manager.encrypt_file_stream(
                        temp_input, encrypted_file, path
                    )
            
            # Update integrity information
            self._update_file_integrity(metadata, encrypted_path)
            self._stats['files_created'] += 1
            
            # Create file handle
            with self._fh_lock:
                fh = self._next_fh
                self._next_fh += 1
                
                self._file_handles[fh] = {
                    'metadata': metadata,
                    'flags': os.O_RDWR,
                    'path': path,
                    'encrypted_path': encrypted_path,
                    'opened_at': time.time()
                }
            
            self.audit_logger.log_file_operation(
                user_id, "CREATE", path, "SUCCESS", session_id,
                {"mode": oct(mode), "file_id": metadata.file_id}
            )
            
            return fh
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_file_operation(
                user_id, "CREATE", path, "ERROR", session_id,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def unlink(self, path):
        """Delete file with secure overwrite."""
        if not self._check_rate_limit("DELETE", LimitType.FILE_OPERATION):
            raise FuseOSError(errno.EACCES)
        
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            # Get metadata
            metadata = self.metadata_manager.get_metadata_by_path(path)
            if not metadata:
                raise FuseOSError(errno.ENOENT)
            
            encrypted_path = self._get_encrypted_path(metadata)
            
            # Secure deletion (DoD 5220.22-M standard)
            if encrypted_path.exists():
                file_size = encrypted_path.stat().st_size
                
                with open(encrypted_path, 'r+b') as f:
                    # Pass 1: Write zeros
                    f.write(b'\x00' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Pass 2: Write ones
                    f.seek(0)
                    f.write(b'\xff' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Pass 3: Write random data
                    f.seek(0)
                    import secrets
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                
                # Remove file
                encrypted_path.unlink()
            
            # Remove metadata
            self.metadata_manager.delete_metadata(metadata.file_id)
            self._stats['files_deleted'] += 1
            
            self.audit_logger.log_file_operation(
                user_id, "DELETE", path, "SUCCESS", session_id,
                {"file_id": metadata.file_id, "secure_deletion": True}
            )
            
        except FuseOSError:
            raise
        except Exception as e:
            self.audit_logger.log_file_operation(
                user_id, "DELETE", path, "ERROR", session_id,
                {"error": str(e)}
            )
            raise FuseOSError(errno.EIO)
    
    def release(self, path, fh):
        """Close file handle."""
        user_id, session_id, ip_address = self._get_user_context()
        
        try:
            if fh in self._file_handles:
                handle_info = self._file_handles[fh]
                
                # Log file close
                self.audit_logger.log_access(
                    user_id, "CLOSE", path, "SUCCESS", session_id, ip_address,
                    {"file_handle": fh, "duration": time.time() - handle_info['opened_at']}
                )
                
                # Remove file handle
                del self._file_handles[fh]
            
        except Exception as e:
            self.audit_logger.log_access(
                user_id, "CLOSE", path, "ERROR", session_id, ip_address,
                {"error": str(e)}
            )
    
    def flush(self, path, fh):
        """Flush file buffers."""
        # Force metadata save
        self.metadata_manager.flush()
        return 0
    
    def fsync(self, path, datasync, fh):
        """Sync file to storage."""
        self.metadata_manager.flush()
        return 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get filesystem statistics."""
        return {
            'filesystem_stats': self._stats,
            'metadata_stats': self.metadata_manager.get_statistics(),
            'rate_limiter_stats': self.rate_limiter.get_global_stats(),
            'active_file_handles': len(self._file_handles)
        }
    
    def shutdown(self):
        """Shutdown filesystem gracefully."""
        self.audit_logger.log_system_event("SYSTEM_STOP", "Secure filesystem unmounting")
        
        # Close all file handles
        for fh in list(self._file_handles.keys()):
            try:
                handle_info = self._file_handles[fh]
                self.release(handle_info['path'], fh)
            except:
                pass
        
        # Shutdown components
        self.metadata_manager.shutdown()
        self.audit_logger.shutdown()
        
        print("🔒 SecureFS shutdown complete")


def mount_secure_filesystem(storage_path: str, mount_point: str, foreground: bool = False):
    """
    Mount the secure filesystem.
    
    Args:
        storage_path: Path to encrypted storage
        mount_point: FUSE mount point
        foreground: Run in foreground for debugging
    """
    storage_path = Path(storage_path)
    mount_point = Path(mount_point)
    
    # Ensure mount point exists
    mount_point.mkdir(exist_ok=True)
    
    # Create filesystem
    secure_fs = SecureFileSystem(storage_path, mount_point)
    
    try:
        # Mount filesystem
        FUSE(
            secure_fs,
            str(mount_point),
            foreground=foreground,
            allow_other=False,  # Security: only allow owner access
            default_permissions=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Received interrupt signal")
    finally:
        secure_fs.shutdown()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python secure_fs.py <storage_path> <mount_point>")
        sys.exit(1)
    
    storage_path = sys.argv[1]
    mount_point = sys.argv[2]
    
    print("🚀 Starting SecureFS...")
    print(f"   Storage: {storage_path}")
    print(f"   Mount: {mount_point}")
    print("   Press Ctrl+C to unmount")
    
    mount_secure_filesystem(storage_path, mount_point, foreground=True)
