"""
Advanced Log Manager with Abuse Detection and Auto-Rotation

Features:
- Automatically creates logs.txt file for all system logs
- Rotates logs after every 10 files (deletes old logs)
- Detects and logs abusive IP addresses and suspicious activities
- Creates special abuse_alerts.log for security monitoring
- Pattern detection for DDoS, SQL injection, excessive requests
- IP reputation tracking and automatic blocking recommendations

Usage:
    from log_manager import LogManager
    
    log_manager = LogManager()
    log_manager.log_request(ip="192.168.1.100", endpoint="/api/data", status=200)
    log_manager.detect_abuse(ip="192.168.1.100")
"""

import os
import time
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional, Tuple

class LogManager:
    """
    Manages application logs with automatic rotation and abuse detection
    """
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_log_files: int = 10,
                 max_log_size_mb: int = 10):
        """
        Initialize the log manager
        
        Args:
            log_dir: Directory to store log files
            max_log_files: Maximum number of log files before rotation
            max_log_size_mb: Maximum size of each log file in MB
        """
        self.log_dir = log_dir
        self.max_log_files = max_log_files
        self.max_log_size_bytes = max_log_size_mb * 1024 * 1024
        
        # Create log directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Log file paths
        self.current_log_file = os.path.join(self.log_dir, "logs.txt")
        self.abuse_log_file = os.path.join(self.log_dir, "abuse_alerts.log")
        
        # Thread safety
        self.lock = Lock()
        
        # Abuse detection tracking
        self.ip_request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.ip_violations: Dict[str, int] = defaultdict(int)
        self.blocked_ips: set = set()
        
        # Suspicious pattern detection
        self.suspicious_patterns = [
            r"(\.\./|\.\.\\)",  # Directory traversal
            r"(union\s+select|select\s+.*\s+from)",  # SQL injection
            r"(<script|javascript:)",  # XSS attempts
            r"(exec\(|eval\()",  # Code injection
            r"(\|\||&&|;|\$\()",  # Command injection
        ]
        
        # Abuse thresholds
        self.REQUESTS_PER_MINUTE_THRESHOLD = 100
        self.REQUESTS_PER_HOUR_THRESHOLD = 1000
        self.ERROR_RATE_THRESHOLD = 0.5  # 50% errors
        self.CONSECUTIVE_FAILURES_THRESHOLD = 20
        
        print(f"✅ LogManager initialized")
        print(f"   Log directory: {self.log_dir}")
        print(f"   Max log files: {self.max_log_files}")
        print(f"   Current log: {self.current_log_file}")
        print(f"   Abuse log: {self.abuse_log_file}")
    
    def log_request(self, 
                   ip: str,
                   endpoint: str,
                   method: str = "GET",
                   status: int = 200,
                   user_agent: str = "",
                   api_key: str = "",
                   response_time_ms: int = 0,
                   **kwargs):
        """
        Log a request with all relevant information
        
        Args:
            ip: Client IP address
            endpoint: API endpoint accessed
            method: HTTP method
            status: HTTP status code
            user_agent: User agent string
            api_key: API key used (if any)
            response_time_ms: Response time in milliseconds
            **kwargs: Additional metadata to log
        """
        timestamp = datetime.now().isoformat()
        
        # Build log entry
        log_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "user_agent": user_agent,
            "api_key": api_key[:20] + "..." if api_key else "",
            "response_time_ms": response_time_ms,
            **kwargs
        }
        
        # Write to main log
        log_line = f"[{timestamp}] {ip} - {method} {endpoint} - Status: {status} - {response_time_ms}ms"
        if api_key:
            log_line += f" - API Key: {api_key[:20]}..."
        log_line += f" - {json.dumps(kwargs)}\n"
        
        with self.lock:
            self._write_log(self.current_log_file, log_line)
            
            # Track for abuse detection
            self.ip_request_history[ip].append({
                "timestamp": time.time(),
                "status": status,
                "endpoint": endpoint,
                "user_agent": user_agent
            })
            
            # Check if rotation needed
            self._check_and_rotate()
        
        # Check for suspicious activity
        self._check_suspicious_activity(ip, endpoint, status, user_agent)
    
    def _write_log(self, filepath: str, content: str):
        """Write content to log file"""
        try:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            print(f"❌ Error writing to log: {e}")
    
    def _check_and_rotate(self):
        """Check if log rotation is needed and perform rotation"""
        if not os.path.exists(self.current_log_file):
            return
        
        # Check file size
        current_size = os.path.getsize(self.current_log_file)
        
        if current_size >= self.max_log_size_bytes:
            self._rotate_logs()
    
    def _rotate_logs(self):
        """Rotate logs by archiving current and deleting old ones"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archived_name = f"logs_{timestamp}.txt"
        archived_path = os.path.join(self.log_dir, archived_name)
        
        # Rename current log to archived log
        if os.path.exists(self.current_log_file):
            os.rename(self.current_log_file, archived_path)
            print(f"📦 Rotated log to: {archived_name}")
        
        # Get all archived logs
        archived_logs = sorted([
            f for f in os.listdir(self.log_dir)
            if f.startswith("logs_") and f.endswith(".txt")
        ])
        
        # Delete old logs if exceeding max count
        while len(archived_logs) > self.max_log_files:
            oldest_log = archived_logs.pop(0)
            oldest_path = os.path.join(self.log_dir, oldest_log)
            os.remove(oldest_path)
            print(f"🗑️  Deleted old log: {oldest_log}")
    
    def _check_suspicious_activity(self, ip: str, endpoint: str, status: int, user_agent: str):
        """Check for suspicious patterns and abuse"""
        suspicious_reasons = []
        
        # Check for malicious patterns in endpoint
        for pattern in self.suspicious_patterns:
            if re.search(pattern, endpoint, re.IGNORECASE):
                suspicious_reasons.append(f"Suspicious pattern detected: {pattern}")
        
        # Check for suspicious user agent
        if not user_agent or len(user_agent) < 10:
            suspicious_reasons.append("Missing or suspicious user agent")
        
        # Check for known attack signatures
        attack_signatures = [
            "nikto", "sqlmap", "nmap", "masscan", "acunetix",
            "havij", "dirbuster", "burp", "metasploit"
        ]
        
        for signature in attack_signatures:
            if signature.lower() in user_agent.lower():
                suspicious_reasons.append(f"Attack tool detected: {signature}")
        
        if suspicious_reasons:
            self._log_abuse(ip, "SUSPICIOUS_ACTIVITY", suspicious_reasons, endpoint)
    
    def detect_abuse(self, ip: str) -> Tuple[bool, List[str]]:
        """
        Detect if an IP is showing abusive behavior
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_abusive, list of reasons)
        """
        if ip in self.blocked_ips:
            return True, ["IP is already blocked"]
        
        abuse_reasons = []
        
        with self.lock:
            history = self.ip_request_history.get(ip, deque())
            
            if not history:
                return False, []
            
            current_time = time.time()
            
            # Check requests per minute
            recent_requests = [
                req for req in history
                if current_time - req["timestamp"] < 60
            ]
            
            if len(recent_requests) > self.REQUESTS_PER_MINUTE_THRESHOLD:
                abuse_reasons.append(
                    f"Excessive requests: {len(recent_requests)} requests in last minute "
                    f"(threshold: {self.REQUESTS_PER_MINUTE_THRESHOLD})"
                )
            
            # Check requests per hour
            hourly_requests = [
                req for req in history
                if current_time - req["timestamp"] < 3600
            ]
            
            if len(hourly_requests) > self.REQUESTS_PER_HOUR_THRESHOLD:
                abuse_reasons.append(
                    f"High request volume: {len(hourly_requests)} requests in last hour "
                    f"(threshold: {self.REQUESTS_PER_HOUR_THRESHOLD})"
                )
            
            # Check error rate
            if recent_requests:
                error_count = sum(1 for req in recent_requests if req["status"] >= 400)
                error_rate = error_count / len(recent_requests)
                
                if error_rate > self.ERROR_RATE_THRESHOLD:
                    abuse_reasons.append(
                        f"High error rate: {error_rate*100:.1f}% "
                        f"(threshold: {self.ERROR_RATE_THRESHOLD*100}%)"
                    )
            
            # Check consecutive failures
            consecutive_failures = 0
            for req in reversed(list(history)):
                if req["status"] >= 400:
                    consecutive_failures += 1
                else:
                    break
            
            if consecutive_failures >= self.CONSECUTIVE_FAILURES_THRESHOLD:
                abuse_reasons.append(
                    f"Consecutive failures: {consecutive_failures} "
                    f"(threshold: {self.CONSECUTIVE_FAILURES_THRESHOLD})"
                )
            
            # Check for endpoint scanning (accessing many different endpoints)
            unique_endpoints = set(req["endpoint"] for req in hourly_requests)
            if len(unique_endpoints) > 50:
                abuse_reasons.append(
                    f"Endpoint scanning detected: {len(unique_endpoints)} unique endpoints accessed"
                )
        
        if abuse_reasons:
            self._log_abuse(ip, "ABUSE_DETECTED", abuse_reasons)
            self.ip_violations[ip] += 1
            
            # Auto-block after multiple violations
            if self.ip_violations[ip] >= 3:
                self.blocked_ips.add(ip)
                self._log_abuse(ip, "IP_BLOCKED", [f"Blocked after {self.ip_violations[ip]} violations"])
        
        return len(abuse_reasons) > 0, abuse_reasons
    
    def _log_abuse(self, ip: str, abuse_type: str, reasons: List[str], extra_info: str = ""):
        """Log abuse to the special abuse log file"""
        timestamp = datetime.now().isoformat()
        
        abuse_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "type": abuse_type,
            "reasons": reasons,
            "violations_count": self.ip_violations[ip],
            "extra_info": extra_info
        }
        
        # Format for human readability
        log_line = f"\n{'='*80}\n"
        log_line += f"🚨 SECURITY ALERT - {abuse_type}\n"
        log_line += f"{'='*80}\n"
        log_line += f"Timestamp: {timestamp}\n"
        log_line += f"IP Address: {ip}\n"
        log_line += f"Violation Count: {self.ip_violations[ip]}\n"
        log_line += f"\nReasons:\n"
        for reason in reasons:
            log_line += f"  • {reason}\n"
        
        if extra_info:
            log_line += f"\nAdditional Info: {extra_info}\n"
        
        log_line += f"\nJSON: {json.dumps(abuse_entry)}\n"
        log_line += f"{'='*80}\n\n"
        
        with self.lock:
            self._write_log(self.abuse_log_file, log_line)
        
        print(f"🚨 ABUSE DETECTED: {ip} - {abuse_type}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.ip_violations[ip] = 0
                self._log_abuse(ip, "IP_UNBLOCKED", ["IP manually unblocked"])
                return True
            return False
    
    def get_abuse_stats(self) -> Dict:
        """Get current abuse statistics"""
        with self.lock:
            return {
                "total_tracked_ips": len(self.ip_request_history),
                "blocked_ips": list(self.blocked_ips),
                "high_violation_ips": {
                    ip: count for ip, count in self.ip_violations.items()
                    if count > 0
                },
                "total_violations": sum(self.ip_violations.values())
            }
    
    def get_ip_history(self, ip: str, limit: int = 100) -> List[Dict]:
        """Get request history for a specific IP"""
        with self.lock:
            history = list(self.ip_request_history.get(ip, deque()))
            return history[-limit:]
    
    def clear_old_history(self, max_age_hours: int = 24):
        """Clear request history older than specified hours"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        with self.lock:
            for ip in list(self.ip_request_history.keys()):
                # Filter out old requests
                old_history = self.ip_request_history[ip]
                new_history = deque(
                    (req for req in old_history if req["timestamp"] > cutoff_time),
                    maxlen=1000
                )
                
                if new_history:
                    self.ip_request_history[ip] = new_history
                else:
                    # Remove IP if no recent history
                    del self.ip_request_history[ip]
            
            print(f"🧹 Cleaned old history. Tracking {len(self.ip_request_history)} IPs")
    
    def get_log_files(self) -> List[Dict]:
        """Get list of all log files with metadata"""
        log_files = []
        
        for filename in os.listdir(self.log_dir):
            filepath = os.path.join(self.log_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                log_files.append({
                    "name": filename,
                    "size_mb": stat.st_size / (1024 * 1024),
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return sorted(log_files, key=lambda x: x["modified"], reverse=True)


# Example usage and testing
if __name__ == "__main__":
    print("🚀 Testing LogManager...")
    
    # Initialize log manager
    log_manager = LogManager(max_log_files=10)
    
    # Simulate normal requests
    print("\n📝 Simulating normal requests...")
    for i in range(5):
        log_manager.log_request(
            ip="192.168.1.100",
            endpoint="/api/data",
            method="GET",
            status=200,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            api_key="test_key_123",
            response_time_ms=45
        )
        time.sleep(0.1)
    
    # Simulate suspicious activity
    print("\n🚨 Simulating suspicious activity...")
    log_manager.log_request(
        ip="192.168.1.200",
        endpoint="/api/users?id=1' OR '1'='1",  # SQL injection attempt
        method="GET",
        status=403,
        user_agent="sqlmap/1.0",
        response_time_ms=10
    )
    
    # Simulate abuse (too many requests)
    print("\n⚠️ Simulating abuse (excessive requests)...")
    for i in range(150):
        log_manager.log_request(
            ip="192.168.1.250",
            endpoint=f"/api/endpoint_{i}",
            method="GET",
            status=200 if i % 3 == 0 else 429,
            user_agent="Python-requests/2.28.0",
            response_time_ms=20
        )
    
    # Check for abuse
    print("\n🔍 Checking for abuse...")
    is_abusive, reasons = log_manager.detect_abuse("192.168.1.250")
    if is_abusive:
        print(f"❌ IP 192.168.1.250 is abusive:")
        for reason in reasons:
            print(f"   • {reason}")
    
    # Get statistics
    print("\n📊 Abuse Statistics:")
    stats = log_manager.get_abuse_stats()
    print(json.dumps(stats, indent=2))
    
    # List log files
    print("\n📁 Log Files:")
    for log_file in log_manager.get_log_files():
        print(f"   • {log_file['name']} - {log_file['size_mb']:.2f} MB")
    
    print("\n✅ Testing complete!")
    print(f"   Check logs directory: {log_manager.log_dir}")
    print(f"   Main log: {log_manager.current_log_file}")
    print(f"   Abuse log: {log_manager.abuse_log_file}")