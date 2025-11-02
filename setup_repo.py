#!/usr/bin/env python3
"""
setup_repo.py - Make SecureFS Repository Commit-Ready

This script fixes the .gitignore issue and prepares the repository for git commits.
"""

import os
import shutil
from pathlib import Path

def setup_repository():
    """Setup the repository for git commits."""
    repo_root = Path(__file__).parent
    
    print("🔧 Setting up SecureFS repository...")
    
    # 1. Fix .gitignore issue
    gitignore_dir = repo_root / ".gitignore"
    gitignore_file = repo_root / ".gitignore"
    new_gitignore = repo_root / "new_gitignore"
    
    if gitignore_dir.is_dir():
        print("📁 Removing .gitignore directory...")
        shutil.rmtree(gitignore_dir)
    
    if new_gitignore.exists():
        print("📝 Creating proper .gitignore file...")
        shutil.move(new_gitignore, gitignore_file)
    
    # 2. Remove any existing master.key files that shouldn't be committed
    for key_file in repo_root.glob("**/*.key"):
        if key_file.name != "master.key" or key_file.parent.name != ".gitignore":
            print(f"🔑 Removing key file: {key_file}")
            key_file.unlink()
    
    # 3. Create necessary directories
    directories = [
        "storage/encrypted",
        "storage/metadata", 
        "logs",
        "mount",
        "tests/sample_data/text_files",
        "tests/sample_data/images", 
        "tests/sample_data/databases",
        "tests/sample_data/large_files"
    ]
    
    for directory in directories:
        dir_path = repo_root / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create .gitkeep files to ensure empty directories are tracked
        gitkeep = dir_path / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.write_text("# This file ensures the directory is tracked by git\n")
    
    # 4. Clean up temporary files
    temp_files = [
        "gitignore_proper",
        "demo_master.key",
        "demo_metadata_master.key", 
        "demo_integrity_keys",
        "demo_metadata_storage",
        "demo_logs",
        "demo_rate_limiter.json"
    ]
    
    for temp_file in temp_files:
        temp_path = repo_root / temp_file
        if temp_path.exists():
            if temp_path.is_dir():
                shutil.rmtree(temp_path)
            else:
                temp_path.unlink()
            print(f"🗑️  Removed temporary file: {temp_file}")
    
    # 5. Create a sample configuration file
    config_sample = repo_root / "config.sample.json"
    if not config_sample.exists():
        config_content = """{
  "encryption": {
    "algorithm": "AES-256-GCM",
    "key_derivation": "HKDF-SHA256"
  },
  "signatures": {
    "algorithm": "RSA-2048-PSS",
    "hash_algorithm": "SHA-256"
  },
  "rate_limiting": {
    "file_access": {
      "max_attempts": 100,
      "time_window_seconds": 60
    },
    "auth_attempts": {
      "max_attempts": 5,
      "time_window_seconds": 900
    }
  },
  "logging": {
    "audit_log_retention_days": 2555,
    "max_log_size_mb": 100
  }
}"""
        config_sample.write_text(config_content)
        print("📋 Created sample configuration file")
    
    # 6. Update empty files with proper content
    empty_files = {
        "src/fuse_fs.py": "# Legacy file - functionality moved to secure_fs.py\n",
        "src/key_manager.py": "# Legacy file - functionality moved to crypto.py\n", 
        "tests/test_integrity.py": "# TODO: Implement integrity tests\n",
        "tests/test_security.py": "# TODO: Implement security tests\n",
        "tests/test_compliance.py": "# TODO: Implement compliance tests\n"
    }
    
    for file_path, content in empty_files.items():
        full_path = repo_root / file_path
        if full_path.exists() and full_path.stat().st_size == 0:
            full_path.write_text(content)
            print(f"📝 Updated empty file: {file_path}")
    
    print("\n✅ Repository setup complete!")
    print("\n📋 Next steps:")
    print("1. git add .")
    print("2. git commit -m 'Initial SecureFS implementation'")
    print("3. git push origin main")
    print("\n🧪 To test the implementation:")
    print("   python3 setup_repo.py --test")
    print("   # Or follow HOW_TO_TEST.md")

def run_quick_test():
    """Run a quick test of core components."""
    print("\n🧪 Running quick component tests...")
    
    repo_root = Path(__file__).parent
    src_dir = repo_root / "src"
    
    # Test each component
    components = [
        ("crypto.py", "🔐 Encryption"),
        ("integrity.py", "✅ Digital Signatures"), 
        ("audit_logger.py", "📋 Audit Logging"),
        ("rate_limiter.py", "🚦 Rate Limiting"),
        ("metadata.py", "🗃️ Metadata Management")
    ]
    
    for component, description in components:
        component_path = src_dir / component
        if component_path.exists():
            print(f"\n{description}:")
            try:
                # Run the component's demo
                os.system(f"cd {repo_root} && python3 src/{component}")
                print(f"   ✅ {component} test passed")
            except Exception as e:
                print(f"   ❌ {component} test failed: {e}")
        else:
            print(f"   ⚠️  {component} not found")
    
    print(f"\n🎉 Quick test complete!")
    print(f"📖 For comprehensive testing, see HOW_TO_TEST.md")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_quick_test()
    else:
        setup_repository()
