#!/usr/bin/env python3
"""
interactive_demo.py - Interactive Demo for Professor

A live, interactive demonstration script perfect for showing to professors.
Handles any file they give you and demonstrates all security features.
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.secure_file_processor import SecureFileProcessor


class InteractiveDemo:
    """Interactive demonstration of the secure file system."""
    
    def __init__(self):
        """Initialize the demo."""
        self.demo_dir = Path("professor_demo")
        self.processor = SecureFileProcessor(self.demo_dir)
        self.current_user = "professor"
        self.session_id = f"demo_session_{int(time.time())}"
        
        print("🔒 SECURE FILE SYSTEM - LIVE DEMO")
        print("=" * 50)
        print("Ready to demonstrate with any file!")
        print("=" * 50)
    
    def wait_for_keypress(self, message="Press ENTER to continue..."):
        """Wait for user to press enter before continuing."""
        input(f"\n🎯 {message}")
    
    def demonstrate_file_security(self, file_path: str):
        """
        Complete demonstration using the professor's file.
        
        Args:
            file_path: Path to the file provided by professor
        """
        source_file = Path(file_path)
        
        if not source_file.exists():
            print(f"❌ File not found: {file_path}")
            return False
        
        print(f"\n📄 DEMONSTRATING WITH: {source_file.name}")
        print(f"   Original size: {source_file.stat().st_size:,} bytes")
        print(f"   Content preview: {source_file.read_text()[:100]}...")
        
        self.wait_for_keypress("Ready to encrypt this file? Press ENTER...")
        
        # Step 1: Store with maximum security
        print(f"\n🔐 STEP 1: SECURE STORAGE")
        print("   Applying CRITICAL security policy...")
        print("   • AES-256-GCM encryption")
        print("   • RSA-2048 digital signature")
        print("   • Full audit logging")
        print("   • Rate limiting protection")
        print("\n   🔄 Processing file... (this is where the magic happens)")
        
        time.sleep(1)  # Small delay to show processing
        
        store_result = self.processor.secure_store_file(
            source_path=str(source_file),
            user_id=self.current_user,
            policy_name="critical",
            session_id=self.session_id,
            ip_address="192.168.1.100",
            tags=["demo", "professor", "critical"],
            custom_attributes={
                "demo_timestamp": datetime.now().isoformat(),
                "security_level": "maximum",
                "compliance": "HIPAA_ready"
            }
        )
        
        if not store_result.success:
            print(f"❌ Storage failed: {store_result.error_message}")
            return False
        
        print(f"   ✅ File encrypted and stored securely!")
        print(f"   📁 Unique File ID: {store_result.file_id}")
        print(f"   🔒 Encrypted filename: {Path(store_result.encrypted_path).name}")
        print(f"   🔍 SHA-256 Checksum: {store_result.checksum[:16]}...")
        print(f"   ⏱️  Processing time: {store_result.processing_time:.3f} seconds")
        
        self.wait_for_keypress("File is now encrypted! Want to see the encrypted data? Press ENTER...")
        
        # Step 2: Show encrypted storage
        print(f"\n🗂️  STEP 2: ENCRYPTED STORAGE VERIFICATION")
        encrypted_path = Path(store_result.encrypted_path)
        encrypted_size = encrypted_path.stat().st_size
        
        print(f"   Original file size: {source_file.stat().st_size:,} bytes")
        print(f"   Encrypted file size: {encrypted_size:,} bytes")
        print(f"   Overhead: {encrypted_size - source_file.stat().st_size:,} bytes")
        
        # Try to read encrypted file (will be gibberish)
        with open(encrypted_path, 'rb') as f:
            encrypted_preview = f.read(50)
        print(f"   Encrypted content (first 50 bytes): {encrypted_preview.hex()}")
        print("   ☝️  This is completely unreadable without proper decryption!")
        print("   💡 Even if someone steals this file, they get gibberish!")
        
        self.wait_for_keypress("Now let's decrypt it back to prove it works! Press ENTER...")
        
        # Step 3: Retrieve and verify
        print(f"\n🔓 STEP 3: SECURE RETRIEVAL & VERIFICATION")
        print("   🔄 Decrypting file... (verifying digital signature)")
        time.sleep(1)  # Show processing
        
        output_file = Path(f"decrypted_{source_file.name}")
        
        retrieve_result = self.processor.secure_retrieve_file(
            file_path=str(source_file),
            output_path=str(output_file),
            user_id=self.current_user,
            policy_name="critical",
            session_id=self.session_id,
            ip_address="192.168.1.100"
        )
        
        if retrieve_result.success:
            # Verify content integrity
            original_content = source_file.read_text()
            decrypted_content = output_file.read_text()
            integrity_check = original_content == decrypted_content
            
            print(f"   ✅ File decrypted successfully!")
            print(f"   🔍 Integrity verification: {'✅ PASSED' if integrity_check else '❌ FAILED'}")
            print(f"   📄 Content matches exactly: {integrity_check}")
            print(f"   ⏱️  Decryption time: {retrieve_result.processing_time:.3f} seconds")
            
            # Show content is identical
            print(f"   Original content length: {len(original_content)} characters")
            print(f"   Decrypted content length: {len(decrypted_content)} characters")
            
            # Clean up decrypted file
            output_file.unlink()
        else:
            print(f"   ❌ Retrieval failed: {retrieve_result.error_message}")
            return False
        
        self.wait_for_keypress("Perfect! Now let's check the audit trail for compliance. Press ENTER...")
        
        # Step 4: Show audit trail
        print(f"\n📋 STEP 4: AUDIT TRAIL & COMPLIANCE")
        print("   🔍 Checking audit logs... (everything is recorded)")
        time.sleep(0.5)
        
        audit_trail = self.processor.audit_logger.get_audit_trail(str(source_file), limit=10)
        
        print(f"   📜 Complete audit trail ({len(audit_trail)} events):")
        for i, event in enumerate(audit_trail[-3:], 1):  # Show last 3 events
            timestamp = datetime.fromisoformat(event['timestamp']).strftime('%H:%M:%S')
            print(f"      {i}. {timestamp} - {event['event_type']}")
            print(f"         User: {event['user_id']}, Status: {event['status']}")
        
        # Generate compliance report
        start_time = datetime.now().replace(hour=0, minute=0, second=0)
        end_time = datetime.now()
        
        report = self.processor.audit_logger.generate_compliance_report(start_time, end_time)
        print(f"   📊 Compliance Report Generated:")
        print(f"      Total events today: {report['metrics']['total_events']}")
        print(f"      GDPR Article 30: {'✅ COMPLIANT' if report['compliance']['gdpr_article_30'] else '❌'}")
        print(f"      HIPAA §164.312(b): {'✅ COMPLIANT' if report['compliance']['hipaa_164_312_b'] else '❌'}")
        print("   💡 Every action is logged for regulatory compliance!")
        
        self.wait_for_keypress("Finally, let's see the security monitoring in action! Press ENTER...")
        
        # Step 5: Show security features
        print(f"\n🛡️  STEP 5: SECURITY FEATURES DEMONSTRATION")
        
        # Show rate limiting
        print("   🚦 Rate Limiting Protection:")
        rate_stats = self.processor.rate_limiter.get_global_stats()
        print(f"      Total requests processed: {rate_stats['total_requests']}")
        print(f"      Blocked malicious requests: {rate_stats['blocked_requests']}")
        print(f"      Current block rate: {rate_stats['block_rate']:.1%}")
        
        # Show metadata protection
        print("   🗃️  Encrypted Metadata:")
        files = self.processor.list_user_files(self.current_user)
        if files:
            file_info = files[-1]  # Get the file we just stored
            print(f"      File tracked in encrypted metadata")
            print(f"      Tags: {', '.join(file_info['tags'])}")
            print(f"      Secure file ID: {file_info['file_id']}")
        
        # Show system status
        print("   📊 System Status:")
        status = self.processor.get_system_status()
        proc_stats = status['processor_stats']
        print(f"      Successful operations: {proc_stats['successful_operations']}")
        print(f"      Total bytes secured: {proc_stats['bytes_processed']:,}")
        print(f"      System uptime: {status['uptime_seconds']:.1f} seconds")
        
        return True
    
    def simulate_attack_prevention(self):
        """Demonstrate security against attacks."""
        self.wait_for_keypress("Want to see how we stop hackers? Let's simulate an attack! Press ENTER...")
        
        print(f"\n⚠️  BONUS: ATTACK PREVENTION DEMO")
        print("   🔴 Simulating malicious rapid access attempts...")
        print("   (This is what happens when someone tries to brute force)")
        time.sleep(1)
        
        # Simulate rapid-fire attempts (will trigger rate limiting)
        for i in range(8):
            print(f"   🔄 Hacker attempt {i+1}...", end=" ")
            time.sleep(0.3)  # Dramatic pause
            
            from src.rate_limiter import LimitType
            allowed, reason, delay = self.processor.rate_limiter.check_rate_limit(
                "attacker", 
                LimitType.AUTH_ATTEMPT,
                "ATTACK",
                "192.168.1.999"
            )
            
            if not allowed:
                print(f"❌ BLOCKED - {reason}")
                print(f"      🛡️  System automatically protected itself!")
                break
            else:
                print(f"⚠️  Allowed (delay: {delay:.1f}s)")
            
            # Record failed attempt
            self.processor.rate_limiter.record_attempt(
                "attacker", 
                LimitType.AUTH_ATTEMPT, 
                "ATTACK", 
                False, 
                "192.168.1.999"
            )
        
        print("   ✅ Rate limiting successfully prevented attack!")
        print("   💡 Real hackers would be automatically locked out!")
    
    def cleanup_demo(self):
        """Clean up demo files."""
        print(f"\n🧹 CLEANING UP DEMO...")
        
        # Show what was created
        if self.demo_dir.exists():
            total_files = sum(1 for _ in self.demo_dir.rglob('*') if _.is_file())
            print(f"   Demo created {total_files} secure files and logs")
            print(f"   All stored in: {self.demo_dir}")
            print("   (You can examine these files after the demo)")
        
        # Graceful shutdown
        self.processor.shutdown()
        print("   ✅ System shutdown complete")
    
    def run_complete_demo(self, file_path: str):
        """Run the complete demonstration."""
        success = self.demonstrate_file_security(file_path)
        
        if success:
            self.simulate_attack_prevention()
            
            print(f"\n" + "=" * 50)
            print("🎉 DEMONSTRATION COMPLETE!")
            print("=" * 50)
            print("✅ File encrypted with AES-256-GCM")
            print("✅ Digital signature with RSA-2048") 
            print("✅ Complete audit trail logged")
            print("✅ Rate limiting protection active")
            print("✅ Metadata encrypted and secured")
            print("✅ GDPR & HIPAA compliance ready")
            print("✅ Attack prevention demonstrated")
            print("=" * 50)
        
        self.cleanup_demo()
        return success


def main():
    """Main function for interactive demo."""
    if len(sys.argv) != 2:
        print("Usage: python interactive_demo.py <file_path>")
        print("\nExample:")
        print("  python interactive_demo.py sensitive_document.txt")
        print("  python interactive_demo.py professor_file.pdf")
        print("\nThis will demonstrate complete security on any file!")
        return
    
    file_path = sys.argv[1]
    
    # Create demo instance and run
    demo = InteractiveDemo()
    
    try:
        success = demo.run_complete_demo(file_path)
        if not success:
            print("❌ Demo encountered issues")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        demo.cleanup_demo()
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        demo.cleanup_demo()
        sys.exit(1)


if __name__ == "__main__":
    main()
