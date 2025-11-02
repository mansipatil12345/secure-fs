"""
src/rate_limiter.py - Rate Limiting & Lockout Policies

Provides comprehensive rate limiting and security controls with:
- Sliding window rate limiting
- Progressive delays and exponential backoff
- Account lockout after failed attempts
- Per-user and global rate limits
- Whitelist/blacklist support
- Real-time monitoring and alerts
"""

import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path


class LimitType(Enum):
    """Types of rate limits."""
    FILE_ACCESS = "FILE_ACCESS"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    FILE_OPERATION = "FILE_OPERATION"
    GLOBAL_OPERATION = "GLOBAL_OPERATION"


@dataclass
class RateLimit:
    """Rate limit configuration."""
    max_attempts: int
    time_window_seconds: int
    lockout_duration_seconds: int
    progressive_delay: bool = True
    max_delay_seconds: int = 300  # 5 minutes


@dataclass
class UserAttempt:
    """Individual user attempt record."""
    timestamp: float
    action: str
    success: bool
    ip_address: Optional[str] = None


@dataclass
class LockoutRecord:
    """User lockout record."""
    user_id: str
    locked_at: float
    unlock_at: float
    reason: str
    attempt_count: int


class RateLimiter:
    """
    Production-ready rate limiter with advanced security features.
    
    Features:
    - Sliding window rate limiting
    - Progressive delays with exponential backoff
    - Account lockout policies
    - IP-based and user-based limits
    - Whitelist/blacklist support
    - Real-time monitoring
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize rate limiter.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or Path("rate_limiter_config.json")
        
        # Thread safety
        self._lock = threading.RLock()
        
        # User attempt tracking
        self._user_attempts: Dict[str, deque] = defaultdict(deque)
        self._ip_attempts: Dict[str, deque] = defaultdict(deque)
        
        # Lockout tracking
        self._locked_users: Dict[str, LockoutRecord] = {}
        self._locked_ips: Dict[str, LockoutRecord] = {}
        
        # Access control lists
        self._whitelisted_users: Set[str] = set()
        self._blacklisted_users: Set[str] = set()
        self._whitelisted_ips: Set[str] = set()
        self._blacklisted_ips: Set[str] = set()
        
        # Rate limit configurations
        self._rate_limits = self._load_default_limits()
        
        # Global statistics
        self._stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'locked_users': 0,
            'start_time': time.time()
        }
        
        # Load configuration if exists
        self._load_config()
    
    def _load_default_limits(self) -> Dict[LimitType, RateLimit]:
        """Load default rate limit configurations."""
        return {
            LimitType.FILE_ACCESS: RateLimit(
                max_attempts=100,
                time_window_seconds=60,
                lockout_duration_seconds=300,  # 5 minutes
                progressive_delay=True,
                max_delay_seconds=60
            ),
            LimitType.AUTH_ATTEMPT: RateLimit(
                max_attempts=5,
                time_window_seconds=900,  # 15 minutes
                lockout_duration_seconds=1800,  # 30 minutes
                progressive_delay=True,
                max_delay_seconds=300
            ),
            LimitType.FILE_OPERATION: RateLimit(
                max_attempts=50,
                time_window_seconds=60,
                lockout_duration_seconds=600,  # 10 minutes
                progressive_delay=True,
                max_delay_seconds=120
            ),
            LimitType.GLOBAL_OPERATION: RateLimit(
                max_attempts=1000,
                time_window_seconds=60,
                lockout_duration_seconds=300,
                progressive_delay=False,
                max_delay_seconds=30
            )
        }
    
    def _load_config(self):
        """Load configuration from file."""
        if not self.config_path.exists():
            self._save_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Load whitelists/blacklists
            self._whitelisted_users = set(config.get('whitelisted_users', []))
            self._blacklisted_users = set(config.get('blacklisted_users', []))
            self._whitelisted_ips = set(config.get('whitelisted_ips', []))
            self._blacklisted_ips = set(config.get('blacklisted_ips', []))
            
            # Load rate limits
            limits_config = config.get('rate_limits', {})
            for limit_type_str, limit_data in limits_config.items():
                try:
                    limit_type = LimitType(limit_type_str)
                    self._rate_limits[limit_type] = RateLimit(**limit_data)
                except (ValueError, TypeError):
                    continue
                    
        except (json.JSONDecodeError, FileNotFoundError):
            self._save_config()
    
    def _save_config(self):
        """Save configuration to file."""
        config = {
            'whitelisted_users': list(self._whitelisted_users),
            'blacklisted_users': list(self._blacklisted_users),
            'whitelisted_ips': list(self._whitelisted_ips),
            'blacklisted_ips': list(self._blacklisted_ips),
            'rate_limits': {
                limit_type.value: {
                    'max_attempts': limit.max_attempts,
                    'time_window_seconds': limit.time_window_seconds,
                    'lockout_duration_seconds': limit.lockout_duration_seconds,
                    'progressive_delay': limit.progressive_delay,
                    'max_delay_seconds': limit.max_delay_seconds
                }
                for limit_type, limit in self._rate_limits.items()
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def _cleanup_old_attempts(self, attempts: deque, time_window: int):
        """Remove attempts outside the time window."""
        current_time = time.time()
        cutoff_time = current_time - time_window
        
        while attempts and attempts[0].timestamp < cutoff_time:
            attempts.popleft()
    
    def _is_whitelisted(self, user_id: str, ip_address: Optional[str] = None) -> bool:
        """Check if user or IP is whitelisted."""
        if user_id in self._whitelisted_users:
            return True
        if ip_address and ip_address in self._whitelisted_ips:
            return True
        return False
    
    def _is_blacklisted(self, user_id: str, ip_address: Optional[str] = None) -> bool:
        """Check if user or IP is blacklisted."""
        if user_id in self._blacklisted_users:
            return True
        if ip_address and ip_address in self._blacklisted_ips:
            return True
        return False
    
    def _calculate_progressive_delay(self, attempts: List[UserAttempt], 
                                   rate_limit: RateLimit) -> float:
        """Calculate progressive delay based on failed attempts."""
        if not rate_limit.progressive_delay:
            return 0.0
        
        # Count recent failed attempts
        current_time = time.time()
        cutoff_time = current_time - rate_limit.time_window_seconds
        
        failed_attempts = sum(
            1 for attempt in attempts 
            if attempt.timestamp >= cutoff_time and not attempt.success
        )
        
        if failed_attempts == 0:
            return 0.0
        
        # Exponential backoff: 2^(failed_attempts - 1) seconds
        delay = min(2 ** (failed_attempts - 1), rate_limit.max_delay_seconds)
        return delay
    
    def check_rate_limit(self, user_id: str, limit_type: LimitType,
                        action: str, ip_address: Optional[str] = None) -> Tuple[bool, str, float]:
        """
        Check if request should be allowed based on rate limits.
        
        Args:
            user_id: User identifier
            limit_type: Type of rate limit to check
            action: Action being performed
            ip_address: Optional IP address
            
        Returns:
            Tuple of (allowed, reason, delay_seconds)
        """
        with self._lock:
            self._stats['total_requests'] += 1
            current_time = time.time()
            
            # Check blacklist first
            if self._is_blacklisted(user_id, ip_address):
                self._stats['blocked_requests'] += 1
                return False, "User or IP is blacklisted", 0.0
            
            # Allow whitelisted users/IPs
            if self._is_whitelisted(user_id, ip_address):
                return True, "Whitelisted", 0.0
            
            # Check if user is currently locked out
            if user_id in self._locked_users:
                lockout = self._locked_users[user_id]
                if current_time < lockout.unlock_at:
                    remaining = lockout.unlock_at - current_time
                    return False, f"User locked out for {remaining:.1f} more seconds", remaining
                else:
                    # Lockout expired, remove it
                    del self._locked_users[user_id]
                    self._stats['locked_users'] -= 1
            
            # Check IP lockout
            if ip_address and ip_address in self._locked_ips:
                lockout = self._locked_ips[ip_address]
                if current_time < lockout.unlock_at:
                    remaining = lockout.unlock_at - current_time
                    return False, f"IP locked out for {remaining:.1f} more seconds", remaining
                else:
                    del self._locked_ips[ip_address]
            
            # Get rate limit configuration
            rate_limit = self._rate_limits.get(limit_type)
            if not rate_limit:
                return True, "No rate limit configured", 0.0
            
            # Clean up old attempts
            user_attempts = self._user_attempts[user_id]
            self._cleanup_old_attempts(user_attempts, rate_limit.time_window_seconds)
            
            if ip_address:
                ip_attempts = self._ip_attempts[ip_address]
                self._cleanup_old_attempts(ip_attempts, rate_limit.time_window_seconds)
            
            # Check user rate limit
            if len(user_attempts) >= rate_limit.max_attempts:
                # Calculate progressive delay
                delay = self._calculate_progressive_delay(list(user_attempts), rate_limit)
                
                # Check if we should lock out the user
                failed_attempts = sum(1 for attempt in user_attempts if not attempt.success)
                if failed_attempts >= rate_limit.max_attempts:
                    self._lock_user(user_id, rate_limit, "Exceeded failed attempt limit")
                
                self._stats['blocked_requests'] += 1
                return False, "Rate limit exceeded", delay
            
            # Check IP rate limit if applicable
            if ip_address and len(self._ip_attempts[ip_address]) >= rate_limit.max_attempts:
                self._stats['blocked_requests'] += 1
                return False, "IP rate limit exceeded", 0.0
            
            return True, "Allowed", 0.0
    
    def record_attempt(self, user_id: str, limit_type: LimitType, action: str,
                      success: bool, ip_address: Optional[str] = None):
        """
        Record an attempt for rate limiting.
        
        Args:
            user_id: User identifier
            limit_type: Type of rate limit
            action: Action performed
            success: Whether the attempt was successful
            ip_address: Optional IP address
        """
        with self._lock:
            current_time = time.time()
            
            # Record user attempt
            attempt = UserAttempt(
                timestamp=current_time,
                action=action,
                success=success,
                ip_address=ip_address
            )
            
            self._user_attempts[user_id].append(attempt)
            
            # Record IP attempt if provided
            if ip_address:
                self._ip_attempts[ip_address].append(attempt)
            
            # Check for lockout conditions on failed attempts
            if not success:
                rate_limit = self._rate_limits.get(limit_type)
                if rate_limit:
                    user_attempts = self._user_attempts[user_id]
                    self._cleanup_old_attempts(user_attempts, rate_limit.time_window_seconds)
                    
                    # Count recent failed attempts
                    recent_failures = sum(
                        1 for att in user_attempts 
                        if not att.success and 
                        att.timestamp >= current_time - rate_limit.time_window_seconds
                    )
                    
                    # Lock user if too many failures
                    if recent_failures >= rate_limit.max_attempts:
                        self._lock_user(user_id, rate_limit, f"Too many failed {action} attempts")
    
    def _lock_user(self, user_id: str, rate_limit: RateLimit, reason: str):
        """Lock out a user."""
        current_time = time.time()
        unlock_time = current_time + rate_limit.lockout_duration_seconds
        
        lockout = LockoutRecord(
            user_id=user_id,
            locked_at=current_time,
            unlock_at=unlock_time,
            reason=reason,
            attempt_count=len(self._user_attempts[user_id])
        )
        
        self._locked_users[user_id] = lockout
        self._stats['locked_users'] += 1
    
    def is_locked_out(self, user_id: str) -> bool:
        """
        Check if user is currently locked out.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user is locked out, False otherwise
        """
        with self._lock:
            if user_id not in self._locked_users:
                return False
            
            lockout = self._locked_users[user_id]
            current_time = time.time()
            
            if current_time >= lockout.unlock_at:
                # Lockout expired
                del self._locked_users[user_id]
                self._stats['locked_users'] -= 1
                return False
            
            return True
    
    def unlock_user(self, user_id: str) -> bool:
        """
        Manually unlock a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user was unlocked, False if not locked
        """
        with self._lock:
            if user_id in self._locked_users:
                del self._locked_users[user_id]
                self._stats['locked_users'] -= 1
                return True
            return False
    
    def reset_user_attempts(self, user_id: str):
        """
        Reset attempt history for a user.
        
        Args:
            user_id: User identifier
        """
        with self._lock:
            if user_id in self._user_attempts:
                self._user_attempts[user_id].clear()
    
    def get_user_stats(self, user_id: str) -> Dict:
        """
        Get statistics for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dictionary with user statistics
        """
        with self._lock:
            attempts = self._user_attempts.get(user_id, deque())
            current_time = time.time()
            
            # Count attempts in last hour
            hour_ago = current_time - 3600
            recent_attempts = [att for att in attempts if att.timestamp >= hour_ago]
            
            stats = {
                'user_id': user_id,
                'total_attempts': len(attempts),
                'recent_attempts_1h': len(recent_attempts),
                'successful_attempts': sum(1 for att in attempts if att.success),
                'failed_attempts': sum(1 for att in attempts if not att.success),
                'is_locked': self.is_locked_out(user_id),
                'is_whitelisted': user_id in self._whitelisted_users,
                'is_blacklisted': user_id in self._blacklisted_users
            }
            
            if user_id in self._locked_users:
                lockout = self._locked_users[user_id]
                stats['lockout_info'] = {
                    'locked_at': datetime.fromtimestamp(lockout.locked_at, timezone.utc).isoformat(),
                    'unlock_at': datetime.fromtimestamp(lockout.unlock_at, timezone.utc).isoformat(),
                    'reason': lockout.reason,
                    'remaining_seconds': max(0, lockout.unlock_at - current_time)
                }
            
            return stats
    
    def list_locked_users(self) -> List[Dict]:
        """
        Get list of currently locked users.
        
        Returns:
            List of locked user information
        """
        with self._lock:
            current_time = time.time()
            locked_users = []
            
            for user_id, lockout in list(self._locked_users.items()):
                if current_time >= lockout.unlock_at:
                    # Remove expired lockout
                    del self._locked_users[user_id]
                    self._stats['locked_users'] -= 1
                    continue
                
                locked_users.append({
                    'user_id': user_id,
                    'locked_at': datetime.fromtimestamp(lockout.locked_at, timezone.utc).isoformat(),
                    'unlock_at': datetime.fromtimestamp(lockout.unlock_at, timezone.utc).isoformat(),
                    'reason': lockout.reason,
                    'remaining_seconds': lockout.unlock_at - current_time
                })
            
            return locked_users
    
    def add_to_whitelist(self, user_id: str):
        """Add user to whitelist."""
        with self._lock:
            self._whitelisted_users.add(user_id)
            self._save_config()
    
    def remove_from_whitelist(self, user_id: str):
        """Remove user from whitelist."""
        with self._lock:
            self._whitelisted_users.discard(user_id)
            self._save_config()
    
    def add_to_blacklist(self, user_id: str):
        """Add user to blacklist."""
        with self._lock:
            self._blacklisted_users.add(user_id)
            # Also lock them out immediately
            rate_limit = self._rate_limits[LimitType.AUTH_ATTEMPT]
            self._lock_user(user_id, rate_limit, "Added to blacklist")
            self._save_config()
    
    def remove_from_blacklist(self, user_id: str):
        """Remove user from blacklist."""
        with self._lock:
            self._blacklisted_users.discard(user_id)
            self._save_config()
    
    def get_global_stats(self) -> Dict:
        """
        Get global rate limiter statistics.
        
        Returns:
            Dictionary with global statistics
        """
        with self._lock:
            current_time = time.time()
            uptime = current_time - self._stats['start_time']
            
            return {
                'uptime_seconds': uptime,
                'total_requests': self._stats['total_requests'],
                'blocked_requests': self._stats['blocked_requests'],
                'block_rate': self._stats['blocked_requests'] / max(1, self._stats['total_requests']),
                'currently_locked_users': len(self._locked_users),
                'total_tracked_users': len(self._user_attempts),
                'whitelisted_users': len(self._whitelisted_users),
                'blacklisted_users': len(self._blacklisted_users),
                'requests_per_second': self._stats['total_requests'] / max(1, uptime)
            }


if __name__ == "__main__":
    # Demo of rate limiting capabilities
    limiter = RateLimiter(Path("demo_rate_limiter.json"))
    
    print("🚦 Rate Limiter Demo")
    
    # Test normal access
    allowed, reason, delay = limiter.check_rate_limit(
        "user123", LimitType.FILE_ACCESS, "READ", "192.168.1.100"
    )
    print(f"Normal access: {'✅ ALLOWED' if allowed else '❌ BLOCKED'} - {reason}")
    
    # Record successful attempt
    limiter.record_attempt("user123", LimitType.FILE_ACCESS, "READ", True, "192.168.1.100")
    
    # Simulate failed authentication attempts
    print("\n🔒 Testing authentication rate limiting...")
    for i in range(6):  # Exceed the limit of 5
        allowed, reason, delay = limiter.check_rate_limit(
            "attacker", LimitType.AUTH_ATTEMPT, "LOGIN", "192.168.1.200"
        )
        limiter.record_attempt("attacker", LimitType.AUTH_ATTEMPT, "LOGIN", False, "192.168.1.200")
        
        if not allowed:
            print(f"Attempt {i+1}: ❌ BLOCKED - {reason} (delay: {delay:.1f}s)")
            break
        else:
            print(f"Attempt {i+1}: ✅ ALLOWED")
    
    # Check lockout status
    is_locked = limiter.is_locked_out("attacker")
    print(f"Attacker locked out: {'✅ YES' if is_locked else '❌ NO'}")
    
    # Get user statistics
    stats = limiter.get_user_stats("attacker")
    print(f"Attacker stats: {stats['failed_attempts']} failed attempts")
    
    # Test whitelist
    limiter.add_to_whitelist("admin")
    allowed, reason, delay = limiter.check_rate_limit(
        "admin", LimitType.FILE_ACCESS, "READ", "192.168.1.50"
    )
    print(f"Whitelisted admin: {'✅ ALLOWED' if allowed else '❌ BLOCKED'} - {reason}")
    
    # Get global statistics
    global_stats = limiter.get_global_stats()
    print(f"\n📊 Global stats: {global_stats['total_requests']} requests, "
          f"{global_stats['blocked_requests']} blocked "
          f"({global_stats['block_rate']:.1%} block rate)")
    
    print("✅ Rate limiter demo completed!")
