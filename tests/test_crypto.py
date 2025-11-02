"""
test_crypto.py - Cryptographic Function Tests

Tests for file encryption at rest functionality.
"""

import pytest
import tempfile
import os
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto import CryptoManager, calculate_file_hash


class TestCryptoManager:
    """Test cases for CryptoManager."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.crypto = CryptoManager(self.temp_dir / "test_master.key")
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Clean up temp files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_master_key_generation(self):
        """Test master key generation and loading."""
        # Key should be generated automatically
        assert self.crypto.master_key is not None
        assert len(self.crypto.master_key) == 32
        
        # Key file should exist with proper permissions
        key_file = self.temp_dir / "test_master.key"
        assert key_file.exists()
        
        # Test loading existing key
        crypto2 = CryptoManager(key_file)
        assert crypto2.master_key == self.crypto.master_key
    
    def test_data_encryption_decryption(self):
        """Test basic data encryption and decryption."""
        plaintext = b"This is sensitive test data!"
        
        # Encrypt data
        file_key, nonce, ciphertext = self.crypto.encrypt_data(plaintext)
        
        # Verify encryption
        assert len(file_key) == 32  # 256-bit key
        assert len(nonce) == 12     # 96-bit nonce for AES-GCM
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)  # Includes auth tag
        
        # Decrypt data
        decrypted = self.crypto.decrypt_data(file_key, nonce, ciphertext)
        assert decrypted == plaintext
    
    def test_key_wrapping(self):
        """Test file key wrapping and unwrapping."""
        file_key = self.crypto.generate_file_key()
        file_path = "/test/document.pdf"
        
        # Wrap key
        nonce, wrapped_key = self.crypto.wrap_file_key(file_key, file_path)
        
        # Verify wrapping
        assert len(nonce) == 12
        assert len(wrapped_key) > 32  # Includes auth tag
        
        # Unwrap key
        unwrapped_key = self.crypto.unwrap_file_key(nonce, wrapped_key, file_path)
        assert unwrapped_key == file_key
    
    def test_file_streaming_encryption(self):
        """Test streaming encryption for large files."""
        # Create test file
        test_file = self.temp_dir / "test_input.txt"
        test_data = b"Hello World! " * 1000  # ~13KB
        test_file.write_bytes(test_data)
        
        # Encrypt file
        encrypted_file = self.temp_dir / "test_encrypted.enc"
        with open(test_file, 'rb') as input_f, open(encrypted_file, 'wb') as output_f:
            metadata = self.crypto.encrypt_file_stream(input_f, output_f, str(test_file))
        
        # Verify encryption metadata
        assert metadata['total_size'] == len(test_data)
        assert metadata['algorithm'] == 'AES-256-GCM'
        assert encrypted_file.exists()
        assert encrypted_file.stat().st_size > len(test_data)
        
        # Decrypt file
        decrypted_file = self.temp_dir / "test_decrypted.txt"
        with open(encrypted_file, 'rb') as input_f, open(decrypted_file, 'wb') as output_f:
            decrypt_metadata = self.crypto.decrypt_file_stream(input_f, output_f, str(test_file))
        
        # Verify decryption
        assert decrypt_metadata['total_size'] == len(test_data)
        decrypted_data = decrypted_file.read_bytes()
        assert decrypted_data == test_data
    
    def test_authentication_failure(self):
        """Test that tampered ciphertext fails authentication."""
        plaintext = b"Secret message"
        file_key, nonce, ciphertext = self.crypto.encrypt_data(plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1  # Flip one bit
        
        # Decryption should fail
        with pytest.raises(Exception):  # Should raise InvalidTag
            self.crypto.decrypt_data(file_key, nonce, bytes(tampered))
    
    def test_different_associated_data(self):
        """Test that different associated data fails authentication."""
        plaintext = b"Secret message"
        file_key = self.crypto.generate_file_key()
        nonce = os.urandom(12)
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(file_key)
        
        # Encrypt with one AAD
        ciphertext = aesgcm.encrypt(nonce, plaintext, b"file1.txt")
        
        # Try to decrypt with different AAD
        with pytest.raises(Exception):  # Should raise InvalidTag
            aesgcm.decrypt(nonce, ciphertext, b"file2.txt")
    
    def test_secure_key_deletion(self):
        """Test secure deletion of cryptographic keys."""
        key_file = self.temp_dir / "test_deletion.key"
        crypto = CryptoManager(key_file)
        
        # Verify key exists
        assert key_file.exists()
        original_size = key_file.stat().st_size
        
        # Secure delete
        crypto.secure_delete_key()
        
        # Key file should be gone
        assert not key_file.exists()


class TestFileHashing:
    """Test cases for file hashing functions."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_file_hash_calculation(self):
        """Test SHA-256 hash calculation."""
        # Create test file
        test_file = self.temp_dir / "hash_test.txt"
        test_data = b"Hello, World!"
        test_file.write_bytes(test_data)
        
        # Calculate hash
        file_hash = calculate_file_hash(test_file)
        
        # Verify hash format
        assert len(file_hash) == 64  # SHA-256 hex digest
        assert all(c in '0123456789abcdef' for c in file_hash)
        
        # Verify consistency
        hash2 = calculate_file_hash(test_file)
        assert file_hash == hash2
        
        # Verify different content gives different hash
        test_file.write_bytes(b"Different content")
        hash3 = calculate_file_hash(test_file)
        assert hash3 != file_hash


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])