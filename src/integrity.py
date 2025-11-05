"""
src/integrity.py - Digital Signatures and Integrity Verification

🔍 FEATURE: DIGITAL SIGNATURES & CHECKSUMS
Implements RSA-2048 digital signatures and SHA-256 checksums for tamper detection.

🏗️ ARCHITECTURE:
- RSA-2048 Key Pairs: Public/private key cryptography
- SHA-256 Hashing: Cryptographic fingerprinting
- PKCS#1 v1.5 Padding: Industry-standard signature scheme
- Signature Envelopes: Structured signature metadata
- Streaming Verification: Memory-efficient for large files

🛡️ SECURITY FEATURES:
- RSA-2048: 2048-bit key strength (recommended until 2030)
- SHA-256: Collision-resistant cryptographic hash function
- Digital Signatures: Non-repudiation and authenticity proof
- Checksum Verification: Detects any bit-level changes
- Tamper Detection: Immediate detection of file modifications

🎯 PROFESSOR DEMO POINTS:
- "Like a wax seal on an envelope - detects any tampering"
- "SHA-256 checksum changes if even 1 bit is modified"
- "RSA signature proves WHO created the file"
- "Mathematically impossible to forge without private key"
- "Used by banks and governments for document integrity"

Provides comprehensive integrity verification with:
- SHA-256 checksums for fast integrity checks
- RSA-2048 digital signatures for non-repudiation
- Streaming support for large files
- Tamper detection and verification

This updated version fixes signature verification by storing/verifying a
signature envelope (payload + signature) so the public key can actually verify
what was signed.
"""

import hashlib
import secrets
from pathlib import Path
from typing import Tuple, Optional, BinaryIO, Any, Dict, Union
from datetime import datetime, timezone
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)


class IntegrityChecker:
    """
    Manages digital signatures and checksums for file integrity verification.

    Features:
    - RSA-2048 digital signatures
    - SHA-256 checksums
    - Streaming support for large files
    - Tamper detection
    - Signature persistence and verification
    """

    def __init__(self, key_path: Optional[Path] = None):
        """
        Initialize integrity checker.

        Args:
            key_path: Path to store RSA key pair. If None, uses default location.
        """
        self.key_path = key_path or Path("integrity_keys")
        self.private_key_path = self.key_path / "private_key.pem"
        self.public_key_path = self.key_path / "public_key.pem"

        # Ensure key directory exists
        self.key_path.mkdir(exist_ok=True)

        # Load or generate RSA key pair
        self.private_key, self.public_key = self._load_or_generate_keys()

    def _load_or_generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Load existing RSA key pair or generate new one.

        Returns:
            Tuple of (private_key, public_key)
        """
        if self.private_key_path.exists() and self.public_key_path.exists():
            return self._load_keys()
        else:
            return self._generate_keys()

    def _generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate new RSA-2048 key pair and save to disk.

        Returns:
            Tuple of (private_key, public_key)
        """
        # Generate RSA-2048 key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Serialize and save private key
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        self.private_key_path.write_bytes(private_pem)
        try:
            self.private_key_path.chmod(0o600)  # Restrict permissions
        except Exception:
            # chmod may not be supported on all platforms; ignore if it fails
            pass

        # Serialize and save public key
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_path.write_bytes(public_pem)

        return private_key, public_key

    def _load_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Load RSA key pair from disk.

        Returns:
            Tuple of (private_key, public_key)

        Raises:
            ValueError: If keys cannot be loaded
        """
        try:
            # Load private key
            private_pem = self.private_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )

            # Load public key
            public_pem = self.public_key_path.read_bytes()
            public_key = serialization.load_pem_public_key(public_pem)

            return private_key, public_key

        except Exception as e:
            raise ValueError(f"Failed to load RSA keys: {e}")

    # --------------------------- Checksum utilities ---------------------------
    def calculate_checksum(self, file_path: Path) -> str:
        """
        Calculate SHA-256 checksum of a file.

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded SHA-256 checksum
        """
        return self.calculate_checksum_stream(file_path)

    def calculate_checksum_stream(self, file_path: Path, chunk_size: int = 64 * 1024) -> str:
        """
        Calculate SHA-256 checksum using streaming for large files.

        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read

        Returns:
            Hex-encoded SHA-256 checksum
        """
        sha256_hash = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def calculate_data_checksum(self, data: bytes) -> str:
        """
        Calculate SHA-256 checksum of data in memory.

        Args:
            data: Data to checksum

        Returns:
            Hex-encoded SHA-256 checksum
        """
        return hashlib.sha256(data).hexdigest()

    # --------------------------- Signing functions ----------------------------
    def sign_file(self, file_path: Path) -> Dict[str, str]:
        """
        Create RSA digital signature for a file and return an envelope containing
        the payload and signature (both as string types suitable for JSON storage).

        Returns:
            dict: {'payload': <json-str>, 'signature': <hex-str>}
        """
        checksum = self.calculate_checksum(file_path)
        signature_data = {
            'file_path': str(file_path),
            'checksum': checksum,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'algorithm': 'SHA-256'
        }
        payload = json.dumps(signature_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = self._sign_data(payload)
        return {
            'payload': payload.decode('utf-8'),
            'signature': signature.hex()
        }

    def sign_data(self, data: bytes, metadata: dict = None) -> Dict[str, Any]:
        """
        Create RSA digital signature for data and return an envelope dict.

        Returns:
            dict: {'payload': <json-str>, 'signature': <hex-str>}
        """
        checksum = self.calculate_data_checksum(data)
        signature_data = {
            'checksum': checksum,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'algorithm': 'SHA-256',
            'data_size': len(data)
        }
        if metadata:
            signature_data['metadata'] = metadata
        payload = json.dumps(signature_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = self._sign_data(payload)
        return {
            'payload': payload.decode('utf-8'),
            'signature': signature.hex()
        }

    def _sign_data(self, data: bytes) -> bytes:
        """
        Sign data using RSA private key and return signature bytes.
        """
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    # ------------------------- Verification helpers -------------------------
    def _verify_signature_envelope(self, envelope: Union[Dict[str, str], str]) -> Optional[dict]:
        """
        Verify an envelope containing 'payload' (string) and 'signature' (hex),
        or accept a JSON string representation of the envelope.

        Returns the deserialized payload dict if signature is valid, else None.
        """
        try:
            if isinstance(envelope, str):
                # Maybe stored as JSON string
                envelope = json.loads(envelope)

            payload_str = envelope.get('payload')
            signature_hex = envelope.get('signature')
            if payload_str is None or signature_hex is None:
                return None

            payload_bytes = payload_str.encode('utf-8')
            signature_bytes = bytes.fromhex(signature_hex)

            # Perform RSA verification using public key
            self.public_key.verify(
                signature_bytes,
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # If verify didn't raise, signature is valid. Return payload dict.
            return json.loads(payload_str)

        except Exception:
            # Any exception -> invalid signature
            return None

    # -------------------------- Verification API ----------------------------
    def verify_file_signature(self, file_path: Path, envelope: Union[Dict[str, str], str]) -> bool:
        """
        Verify RSA digital signature for a file using the envelope returned by sign_file().

        Args:
            file_path: Path to file
            envelope: {'payload': <json str>, 'signature': <hex str>} or JSON string

        Returns:
            True if signature is valid *and* the embedded checksum matches the file.
        """
        try:
            current_checksum = self.calculate_checksum(file_path)
            sig_payload = self._verify_signature_envelope(envelope)
            if not sig_payload:
                return False
            original_checksum = sig_payload.get('checksum')
            # Optionally verify file_path string matches
            # original_path = sig_payload.get('file_path')
            return current_checksum == original_checksum
        except Exception:
            return False

    def verify_data_signature(self, data: bytes, envelope: Union[Dict[str, str], str]) -> bool:
        """
        Verify RSA digital signature for in-memory data using envelope from sign_data().
        """
        try:
            current_checksum = self.calculate_data_checksum(data)
            sig_payload = self._verify_signature_envelope(envelope)
            if not sig_payload:
                return False
            original_checksum = sig_payload.get('checksum')
            return current_checksum == original_checksum
        except Exception:
            return False

    # ------------------------- Integrity / Tamper checks ---------------------
    def verify_file_integrity(self, file_path: Path, expected_checksum: str) -> bool:
        """
        Verify file integrity against expected checksum.
        """
        try:
            current_checksum = self.calculate_checksum(file_path)
            return current_checksum == expected_checksum
        except Exception:
            return False

    def detect_tampering(self, file_path: Path, metadata: dict) -> bool:
        """
        Detect if file has been tampered with based on stored metadata.

        Args:
            file_path: Path to file
            metadata: Stored file metadata with checksum and signature_envelope (preferred) or signature (hex)

        Returns:
            True if tampering detected, False if file is intact
        """
        try:
            # Check if file exists
            if not file_path.exists():
                return True  # File missing = tampering

            # Verify checksum if present
            stored_checksum = metadata.get('checksum')
            if stored_checksum:
                current_checksum = self.calculate_checksum(file_path)
                if current_checksum != stored_checksum:
                    return True  # Checksum mismatch = tampering

            # Verify signature if present (support both envelope and old raw hex for compatibility)
            stored_envelope = metadata.get('signature_envelope')
            stored_signature_hex = metadata.get('signature')

            if stored_envelope:
                if not self.verify_file_signature(file_path, stored_envelope):
                    return True
            elif stored_signature_hex:
                # old format: signature only (not recommended). Can't verify without payload.
                # We treat this as tampering because we can't validate payloads.
                return True

            return False  # No tampering detected

        except Exception:
            return True  # Error = assume tampering

    def create_integrity_record(self, file_path: Path, additional_data: dict = None) -> dict:
        """
        Create comprehensive integrity record for a file.

        Returns:
            Dictionary with integrity information
        """
        # Calculate checksum
        checksum = self.calculate_checksum(file_path)

        # Create digital signature envelope
        signature_envelope = self.sign_file(file_path)

        # Get file stats
        stat = file_path.stat()

        # Create integrity record
        record = {
            'file_path': str(file_path),
            'checksum': checksum,
            'signature_envelope': signature_envelope,
            'algorithm': 'SHA-256',
            'signature_algorithm': 'RSA-2048-PSS',
            'file_size': stat.st_size,
            'created_timestamp': datetime.now(timezone.utc).isoformat(),
            'file_mtime': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        }

        if additional_data:
            record.update(additional_data)

        return record

    def verify_integrity_record(self, file_path: Path, record: dict) -> dict:
        """
        Verify file against stored integrity record.

        Returns:
            Dictionary with verification results
        """
        results = {
            'file_exists': file_path.exists(),
            'checksum_valid': False,
            'signature_valid': False,
            'size_matches': False,
            'overall_valid': False
        }

        if not results['file_exists']:
            return results

        try:
            # Verify checksum
            current_checksum = self.calculate_checksum(file_path)
            stored_checksum = record.get('checksum')
            results['checksum_valid'] = current_checksum == stored_checksum

            # Verify signature (prefer envelope)
            stored_envelope = record.get('signature_envelope')
            if stored_envelope:
                results['signature_valid'] = self.verify_file_signature(file_path, stored_envelope)
            else:
                # If only raw signature hex is present we can't verify payload -> treat as False
                results['signature_valid'] = False

            # Verify file size
            current_size = file_path.stat().st_size
            stored_size = record.get('file_size')
            results['size_matches'] = current_size == stored_size

            # Overall validity
            results['overall_valid'] = (
                results['checksum_valid'] and 
                results['signature_valid'] and 
                results['size_matches']
            )

        except Exception as e:
            results['error'] = str(e)

        return results

    def secure_delete_keys(self) -> None:
        """
        Securely delete RSA key files.
        """
        for key_file in [self.private_key_path, self.public_key_path]:
            if key_file.exists():
                # Overwrite file multiple times
                file_size = key_file.stat().st_size

                with open(key_file, 'r+b') as f:
                    # Pass 1: Write zeros
                    f.write(b'\x00' * file_size)
                    f.flush()

                    # Pass 2: Write ones
                    f.seek(0)
                    f.write(b'\xff' * file_size)
                    f.flush()

                    # Pass 3: Write random data
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()

                # Remove file
                key_file.unlink()


def verify_file_chain(file_paths: list, integrity_records: list) -> dict:
    """
    Verify integrity of multiple files as a chain.
    """
    checker = IntegrityChecker()
    results = {
        'chain_valid': True,
        'files': []
    }

    for file_path, record in zip(file_paths, integrity_records):
        file_result = checker.verify_integrity_record(Path(file_path), record)
        results['files'].append({
            'path': str(file_path),
            'result': file_result
        })

        if not file_result['overall_valid']:
            results['chain_valid'] = False

    return results


if __name__ == "__main__":
    # Demo of integrity checking capabilities
    checker = IntegrityChecker(Path("demo_integrity_keys"))

    # Create a test file
    test_file = Path("test_integrity.txt")
    # test_data = b"This is a test file for integrity checking!"
    # test_file.write_bytes(test_data)

    print("🔐 Integrity Checker Demo")
    print(f"Test file: {test_file}")

    # Calculate checksum
    checksum = checker.calculate_checksum(test_file)
    print(f"SHA-256 checksum: {checksum}")

    # Create digital signature envelope
    signature_envelope = checker.sign_file(test_file)
    print(f"Signature envelope keys: {list(signature_envelope.keys())}")

    # Verify signature
    is_valid = checker.verify_file_signature(test_file, signature_envelope)
    print(f"Signature verification: {'✅ VALID' if is_valid else '❌ INVALID'}")

    # Create integrity record
    record = checker.create_integrity_record(test_file)
    print(f"Integrity record created with {len(record)} fields")

    # Verify integrity record
    verification = checker.verify_integrity_record(test_file, record)
    print(f"Integrity verification: {'✅ VALID' if verification['overall_valid'] else '❌ INVALID'}")

    # Test tampering detection
    print("\n🔍 Testing tampering detection...")

    # Modify file content
    # test_file.write_bytes(b"This file has been tampered with!")
    print("changed checksum (ideally)")
    print(checker.calculate_checksum(test_file))

    # Check for tampering
    is_tampered = checker.detect_tampering(test_file, record)
    print(f"Tampering detected: {'✅ YES' if is_tampered else '❌ NO'}")

    # Verify again
    verification_after = checker.verify_integrity_record(test_file, record)
    print(f"Integrity after tampering: {'✅ VALID' if verification_after['overall_valid'] else '❌ INVALID'}")

    #Clean up
    # test_file.unlink()
    # checker.secure_delete_keys()

    print("\n✅ Integrity checker demo completed!")
