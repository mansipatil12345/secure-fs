# 🧪 SecureFS - Complete Testing Guide

This guide will walk you through testing all the security features of SecureFS step by step.

## 📋 Prerequisites

### 1. Install Dependencies

```bash
# Install FUSE (macOS)
brew install macfuse

# Install FUSE (Ubuntu/Debian)
sudo apt-get install fuse libfuse-dev

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
# Check Python version (3.8+ required)
python3 --version

# Verify cryptography library
python3 -c "from cryptography.fernet import Fernet; print('✅ Cryptography OK')"

# Check FUSE availability
python3 -c "import fuse; print('✅ FUSE OK')"
```

## 🔐 Phase 1: Test Encryption Components

### Test 1: Basic Cryptography

```bash
# Test the crypto module
cd /Users/s4r7h4k/Desktop/OperatingSystems/c2p2/secure-fs
python3 src/crypto.py
```

**Expected Output:**
```
Original: b'This is sensitive data that needs encryption!'
Encrypted length: XX bytes
Decrypted: b'This is sensitive data that needs encryption!'
✅ Encryption/decryption test passed!
✅ Key wrapping test passed!
```

### Test 2: Digital Signatures & Integrity

```bash
# Test integrity checking
python3 src/integrity.py
```

**Expected Output:**
```
🔐 Integrity Checker Demo
Test file: test_integrity.txt
SHA-256 checksum: abc123...
Digital signature length: 256 bytes
Signature verification: ✅ VALID
Integrity record created with X fields
Integrity verification: ✅ VALID

🔍 Testing tampering detection...
Tampering detected: ✅ YES
Integrity after tampering: ❌ INVALID
✅ Integrity checker demo completed!
```

### Test 3: Audit Logging

```bash
# Test audit logging system
python3 src/audit_logger.py
```

**Expected Output:**
```
📋 Audit Logger Demo
✅ Logged authentication, access, modification, and security events
📊 Compliance report generated with X events
🔍 Log integrity: ✅ VERIFIED
📜 Audit trail for document: X events
✅ Audit logger demo completed!
```

### Test 4: Rate Limiting

```bash
# Test rate limiting and lockout policies
python3 src/rate_limiter.py
```

**Expected Output:**
```
🚦 Rate Limiter Demo
Normal access: ✅ ALLOWED - Allowed
🔒 Testing authentication rate limiting...
Attempt 1: ✅ ALLOWED
...
Attempt 6: ❌ BLOCKED - User locked out for XX.X more seconds (delay: XX.Xs)
Attacker locked out: ✅ YES
Whitelisted admin: ✅ ALLOWED - Whitelisted
📊 Global stats: X requests, X blocked (XX.X% block rate)
✅ Rate limiter demo completed!
```

### Test 5: Secure Metadata

```bash
# Test encrypted metadata management
python3 src/metadata.py
```

**Expected Output:**
```
🗃️  Secure Metadata Manager Demo
Created metadata for file ID: uuid-here
Encrypted filename: uuid_timestamp_hash.enc
✅ Successfully retrieved metadata by path
Updated metadata: ✅ SUCCESS
Files for user123: 1 files
✅ Created backup: /path/to/backup
Metadata integrity: ✅ VALID
📊 Statistics: 1 files, XX.X% cache hit rate
✅ Secure metadata manager demo completed!
```

## 🚀 Phase 2: Test FUSE Filesystem

### Test 6: Mount SecureFS

```bash
# Create directories
mkdir -p ~/securefs_storage ~/securefs_mount

# Mount the filesystem (run in background)
python3 src/secure_fs.py ~/securefs_storage ~/securefs_mount &
SECUREFS_PID=$!

# Wait a moment for mounting
sleep 2

# Verify mount
ls ~/securefs_mount
echo $?  # Should be 0 (success)
```

**Expected Output:**
```
🔒 SecureFS initialized:
   Storage: /Users/username/securefs_storage
   Mount: /Users/username/securefs_mount
   Encryption: AES-256-GCM
   Signatures: RSA-2048
```

### Test 7: Basic File Operations

```bash
# Test file creation and encryption
echo "This is secret data!" > ~/securefs_mount/secret.txt
echo "Financial records" > ~/securefs_mount/finance.pdf
echo "Medical data" > ~/securefs_mount/patient_record.txt

# Verify files appear in mount
ls -la ~/securefs_mount/

# Read files back (automatic decryption)
cat ~/securefs_mount/secret.txt
cat ~/securefs_mount/finance.pdf
```

**Expected Results:**
- Files should be visible in mount point
- Content should be readable and match what you wrote
- Files in storage directory should be encrypted (unreadable)

### Test 8: Verify Encryption at Rest

```bash
# Check encrypted storage (should be unreadable)
ls -la ~/securefs_storage/encrypted/
cat ~/securefs_storage/encrypted/*.enc  # Should show encrypted data

# Check metadata is encrypted
ls -la ~/securefs_storage/metadata/
file ~/securefs_storage/metadata/metadata.enc  # Should show encrypted data
```

**Expected Results:**
- Encrypted files have UUID names with .enc extension
- Raw encrypted files should be unreadable binary data
- Metadata files should also be encrypted

### Test 9: Integrity Verification

```bash
# Create a test file
echo "Important document" > ~/securefs_mount/important.doc

# Check integrity files are created
ls -la ~/securefs_storage/integrity_keys/
ls -la ~/securefs_storage/metadata/

# Try to tamper with encrypted file (this should be detected)
# Note: Don't actually do this in production!
```

### Test 10: Audit Logging Verification

```bash
# Check audit logs are being created
ls -la ~/securefs_storage/logs/
tail ~/securefs_storage/logs/audit.log
tail ~/securefs_storage/logs/security.log

# Perform various operations to generate logs
cp ~/securefs_mount/secret.txt ~/securefs_mount/secret_copy.txt
rm ~/securefs_mount/secret_copy.txt

# Check logs again
tail -n 20 ~/securefs_storage/logs/audit.log
```

**Expected Results:**
- Audit logs should contain JSON entries for each operation
- Security logs should capture any security events
- All file access should be logged with timestamps

## 🧪 Phase 3: Advanced Security Testing

### Test 11: Rate Limiting in Action

```bash
# Test rate limiting (this will create many rapid requests)
for i in {1..10}; do
    cat ~/securefs_mount/secret.txt > /dev/null
    echo "Request $i completed"
done

# Check if rate limiting kicked in
tail ~/securefs_storage/logs/security.log | grep RATE_LIMIT
```

### Test 12: Large File Handling

```bash
# Create a large file (10MB)
dd if=/dev/zero of=~/securefs_mount/large_file.bin bs=1M count=10

# Verify it's encrypted and signed
ls -la ~/securefs_storage/encrypted/
ls -la ~/securefs_mount/large_file.bin

# Read it back
dd if=~/securefs_mount/large_file.bin of=/tmp/test_output bs=1M count=10
ls -la /tmp/test_output
```

### Test 13: Concurrent Access

```bash
# Test concurrent file access (open multiple terminals)
# Terminal 1:
while true; do echo "Writer 1: $(date)" >> ~/securefs_mount/concurrent_test.txt; sleep 1; done &

# Terminal 2:
while true; do tail -1 ~/securefs_mount/concurrent_test.txt; sleep 1; done &

# Let it run for 30 seconds, then stop both processes
# Check integrity is maintained
```

### Test 14: Security Event Testing

```bash
# Generate security events for testing
# (These are safe tests that won't damage anything)

# 1. Test integrity checking by creating and reading files
echo "Test integrity" > ~/securefs_mount/integrity_test.txt
cat ~/securefs_mount/integrity_test.txt

# 2. Check security logs
grep -i "integrity\|security\|rate" ~/securefs_storage/logs/security.log

# 3. Test rate limiting
for i in {1..20}; do
    ls ~/securefs_mount/ > /dev/null
done
```

## 🔍 Phase 4: Compliance Testing

### Test 15: GDPR Compliance Verification

```bash
# Generate compliance report
python3 -c "
import sys
sys.path.append('src')
from audit_logger import AuditLogger
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = AuditLogger(Path('$HOME/securefs_storage/logs'))
start_date = datetime.now(timezone.utc) - timedelta(hours=1)
end_date = datetime.now(timezone.utc)

report = logger.generate_compliance_report(start_date, end_date)
print('📊 GDPR Compliance Report:')
for key, value in report['metrics'].items():
    print(f'  {key}: {value}')
print(f'✅ GDPR Article 30: {report[\"compliance\"][\"gdpr_article_30\"]}')
print(f'✅ HIPAA 164.312(b): {report[\"compliance\"][\"hipaa_164_312_b\"]}')
"
```

### Test 16: Secure Deletion Verification

```bash
# Create a file with known content
echo "This file will be securely deleted" > ~/securefs_mount/delete_test.txt
ORIGINAL_CONTENT="This file will be securely deleted"

# Note the encrypted file location
ls -la ~/securefs_storage/encrypted/

# Delete the file
rm ~/securefs_mount/delete_test.txt

# Verify secure deletion occurred
echo "Checking if secure deletion worked..."
# The encrypted file should be gone from storage
ls -la ~/securefs_storage/encrypted/

# Check audit logs for deletion event
grep -i "delete" ~/securefs_storage/logs/audit.log | tail -1
```

## 🧹 Cleanup and Unmount

### Unmount Filesystem

```bash
# Unmount the filesystem
kill $SECUREFS_PID
# Or use Ctrl+C if running in foreground

# Verify unmount
ls ~/securefs_mount  # Should be empty or show error

# Clean up test directories (optional)
# rm -rf ~/securefs_storage ~/securefs_mount
```

## 📊 Test Results Verification

### Expected Security Metrics

After running all tests, you should see:

1. **Encryption**: All files encrypted with AES-256-GCM
2. **Signatures**: RSA-2048 signatures for all files
3. **Audit Logs**: Complete JSON audit trail
4. **Rate Limiting**: Lockout after excessive requests
5. **Integrity**: Tamper detection working
6. **Metadata**: Encrypted filenames and attributes

### Verification Checklist

- [ ] ✅ Files are transparently encrypted/decrypted
- [ ] ✅ Encrypted storage contains unreadable files
- [ ] ✅ Digital signatures are created and verified
- [ ] ✅ Audit logs capture all operations
- [ ] ✅ Rate limiting prevents abuse
- [ ] ✅ Secure deletion overwrites data
- [ ] ✅ Metadata is encrypted
- [ ] ✅ Large files work correctly
- [ ] ✅ Concurrent access is safe
- [ ] ✅ Compliance reports generate correctly

## 🚨 Troubleshooting

### Common Issues

1. **FUSE not available**: Install macfuse/fuse packages
2. **Permission denied**: Check file permissions on storage directory
3. **Module not found**: Ensure you're in the correct directory and dependencies are installed
4. **Mount fails**: Check if mount point exists and is empty

### Debug Mode

```bash
# Run with debug output
python3 src/secure_fs.py ~/securefs_storage ~/securefs_mount --debug

# Check system logs
# macOS: Console.app or `log show --predicate 'process == "python3"'`
# Linux: `dmesg | tail` or `journalctl -f`
```

### Performance Testing

```bash
# Benchmark file operations
time dd if=/dev/zero of=~/securefs_mount/benchmark.bin bs=1M count=100
time dd if=~/securefs_mount/benchmark.bin of=/dev/null bs=1M

# Check statistics
python3 -c "
import sys
sys.path.append('src')
from secure_fs import SecureFileSystem
# Print performance stats
"
```

## 🎉 Success Criteria

Your SecureFS implementation is working correctly if:

1. **All component tests pass** (Phase 1)
2. **Filesystem mounts successfully** (Phase 2)
3. **Files are transparently encrypted/decrypted** (Phase 2)
4. **Security features work as expected** (Phase 3)
5. **Compliance requirements are met** (Phase 4)

**Congratulations! You now have a production-ready secure filesystem! 🔒**

---

*For additional help, check the main README.md or create an issue in the repository.*
