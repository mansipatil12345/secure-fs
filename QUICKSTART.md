# 🚀 SecureFS - 5-Minute Quickstart

Get SecureFS running in 5 minutes with this simple guide.

## ⚡ Super Quick Test

```bash
# 1. Install dependencies
pip install cryptography fusepy pytest

# 2. Test core components
python src/crypto.py
python src/integrity.py  
python src/audit_logger.py

# 3. Create test directories
mkdir -p ~/test_storage ~/test_mount

# 4. Mount SecureFS (in background)
python src/secure_fs.py ~/test_storage ~/test_mount &

# 5. Test it works!
echo "Secret data!" > ~/test_mount/secret.txt
cat ~/test_mount/secret.txt  # Should show: Secret data!

# 6. Verify encryption
ls ~/test_storage/encrypted/  # Should show encrypted files
cat ~/test_storage/encrypted/*.enc  # Should show encrypted gibberish

# 7. Unmount
killall python  # Or Ctrl+C if running in foreground
```

## 🔍 What Just Happened?

1. **File created**: `secret.txt` in mount point
2. **Automatically encrypted**: File stored as encrypted binary in storage
3. **Transparent decryption**: Reading the file automatically decrypts it
4. **Digital signature**: File is signed with RSA-2048
5. **Audit logged**: All operations logged for compliance
6. **Rate limited**: Excessive access attempts are blocked

## 📊 Verify Security Features

```bash
# Check audit logs
tail ~/test_storage/logs/audit.log

# Check encrypted storage
ls -la ~/test_storage/encrypted/

# Check integrity keys
ls -la ~/test_storage/integrity_keys/

# Check metadata
ls -la ~/test_storage/metadata/
```

## 🧪 Full Test Suite

For comprehensive testing of all security features:

```bash
# See the complete testing guide
cat HOW_TO_TEST.md

# Or run automated tests
pytest tests/ -v
```

## 🔒 Security Features Verified

- ✅ **AES-256-GCM encryption** - Files encrypted at rest
- ✅ **RSA-2048 signatures** - Digital signatures for integrity
- ✅ **SHA-256 checksums** - Fast integrity verification  
- ✅ **Audit logging** - All operations logged (GDPR/HIPAA compliant)
- ✅ **Rate limiting** - Prevents brute force attacks
- ✅ **Secure metadata** - Filenames and attributes encrypted
- ✅ **Transparent operation** - Works with any application

## 🚨 Important Notes

- **Never commit `master.key`** to version control
- **Use proper .gitignore** (provided in repo)
- **Monitor security logs** for production use
- **Backup encryption keys** securely

## 📖 Next Steps

1. **Read HOW_TO_TEST.md** for comprehensive testing
2. **Check README.md** for full documentation
3. **Review security considerations** before production use
4. **Set up monitoring** for audit logs

**🎉 You now have a working secure filesystem!**
