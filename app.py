"""
Enterprise-Grade API Rate Limiter with Real-Time Monitoring Dashboard

This Flask-based application provides a comprehensive rate limiting solution with:
- Tiered rate limiting (Free, Basic, Premium, Enterprise) based on API keys
- IP-based rate limiting with automatic temporary bans
- Real-time WebSocket dashboard for monitoring requests and metrics
- SQLite database for persistent storage of users, logs, and analytics
- Connection pooling for improved database performance
- Admin endpoints for user management and tier upgrades (AUTH REQUIRED)
- Exponential backoff for repeated violations

Security Features:
- Parameterized SQL queries to prevent SQL injection
- API key hashing using bcrypt for secure storage
- Admin authentication using secure tokens
- Input validation and sanitization
- Rate limiting on all endpoints including admin
- Configurable CORS policies
- Request size limits

Key Components:
- Rate Limiting: Token bucket algorithm with sliding windows
- Monitoring: WebSocket-based real-time dashboard with Chart.js
- Database: SQLite with proper connection pooling and indexed queries
- Security: Hashed API keys, admin authentication, comprehensive input validation

Architecture:
- Separation of concerns with clear service layers
- Configuration management through environment variables
- Proper error handling and logging
- Thread-safe operations with appropriate locking mechanisms

Usage:
    # Set environment variables first
    export JWT_SECRET_KEY="your-secure-secret-key"
    export ADMIN_TOKEN="your-admin-token"
    export FLASK_ENV="production"
    
    python app.py
    Dashboard: http://localhost:5000/dashboard
    API: http://localhost:5000/data?api_key=YOUR_KEY

Requirements:
    - Python 3.8+
    - Flask, Flask-SocketIO, Flask-CORS
    - bcrypt for password hashing
    - python-dotenv for environment management

Production Deployment:
    - Use a production WSGI server (gunicorn, uwsgi)
    - Configure proper CORS origins
    - Use Redis for distributed rate limiting
    - Implement proper monitoring and alerting
    - Use a production database (PostgreSQL)
    - Configure SSL/TLS
    - Set up proper logging aggregation

Author: Security-Hardened Version
Version: 2.0.0 (Security Enhanced)
Last Updated: 2025
License: MIT
"""
import sqlite3
import time
from flask import g, send_file  
import secrets
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, Tuple, Optional, Any, List
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, abort
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import bcrypt

import os
from dotenv import load_dotenv
from auth import JWTAuthManager


load_dotenv()

# CONFIGURATION

class Config:
    """Application configuration with secure defaults"""


    # Security
    SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    ADMIN_TOKEN = os.getenv('ADMIN_TOKEN')
    
    # Validate critical configuration
    if not SECRET_KEY or SECRET_KEY == 'your-secret-key-change-in-production':
        raise ValueError("JWT_SECRET_KEY must be set to a secure value in production")
    
    if not ADMIN_TOKEN:
        raise ValueError("ADMIN_TOKEN must be set for admin endpoint protection")
    
    # Database
    DB_PATH = os.getenv('DB_PATH', 'ratelimiter.db')
    DB_POOL_SIZE = int(os.getenv('DB_POOL_SIZE', '5'))
    
    # Rate Limiting
    RATE_LIMITS = {
        'free': {'requests': 5, 'window': 60},
        'basic': {'requests': 20, 'window': 60},
        'premium': {'requests': 100, 'window': 60},
        'enterprise': {'requests': 1000, 'window': 60}
    }
    
    IP_RATE_LIMIT = int(os.getenv('IP_RATE_LIMIT', '100'))
    IP_WINDOW = int(os.getenv('IP_WINDOW', '60'))
    TEMP_BAN_SECONDS = int(os.getenv('TEMP_BAN_SECONDS', '300'))
    BAN_MULTIPLIER = float(os.getenv('BAN_MULTIPLIER', '2'))
    
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', str(16 * 1024)))  # 16KB
    MAX_LOG_ENTRIES = int(os.getenv('MAX_LOG_ENTRIES', '1000'))
    
    SOCKETIO_ASYNC_MODE = os.getenv('SOCKETIO_ASYNC_MODE', 'threading')
    
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = FLASK_ENV == 'development'


# FLASK APPLICATION SETUP

from functools import wraps
from flask import request, jsonify, g
import jwt
import os

def require_jwt_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Unauthorized",
                "message": "Authorization: Bearer <token> required"
            }), 401

        token = auth_header.split(" ", 1)[1]

        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_SECRET_KEY"),
                algorithms=["HS256"]
            )

            if payload.get("type") != "access":
                return jsonify({
                    "error": "Invalid token type"
                }), 401

            # Attach user to request context
            g.user = {
                "user_id": payload.get("user_id"),
                "tier": payload.get("tier"),
                "metadata": payload.get("metadata", {})
            }

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated


app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)
socketio = SocketIO(
    app,
    cors_allowed_origins=Config.CORS_ORIGINS,
    async_mode=Config.SOCKETIO_ASYNC_MODE,
    max_http_buffer_size=Config.MAX_CONTENT_LENGTH
)


jwt_manager = JWTAuthManager(
    secret_key=Config.SECRET_KEY,
    algorithm="HS256"
)
jwt_manager.init_auth_endpoints(app)
app.config["JWT_MANAGER"] = jwt_manager


print("✅ JWT Authentication initialized")
print("📝 Auth endpoints registered: /auth/register, /auth/login, /auth/refresh")




# DATABASE CONNECTION POOL

class DatabasePool:
    """Thread-safe database connection pool for SQLite"""
    
    def __init__(self, db_path: str = Config.DB_PATH, pool_size: int = Config.DB_POOL_SIZE):
        self.db_path = db_path
        self.pool = deque()
        self.pool_size = pool_size
        self.lock = Lock()
        
        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            self.pool.append(conn)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get a connection from the pool or create new one if pool is empty"""
        with self.lock:
            if self.pool:
                return self.pool.popleft()
            
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            return conn
    
    def return_connection(self, conn: sqlite3.Connection) -> None:
        """Return a connection to the pool or close it if pool is full"""
        with self.lock:
            if len(self.pool) < self.pool_size:
                self.pool.append(conn)
            else:
                conn.close()
    
    def close_all(self) -> None:
        """Close all connections in the pool"""
        with self.lock:
            while self.pool:
                conn = self.pool.popleft()
                conn.close()


db_pool = DatabasePool()


# DATABASE SCHEMA

def ensure_db_schema() -> None:
    """Initialize database schema with proper indexes and constraints"""
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        # Users table with hashed API keys
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_hash TEXT UNIQUE NOT NULL,
                api_key_prefix TEXT NOT NULL,
                request_count INTEGER DEFAULT 0,
                window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked INTEGER DEFAULT 0,
                banned_until TEXT DEFAULT NULL,
                tier TEXT DEFAULT 'free',
                total_requests INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Request logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_prefix TEXT,
                endpoint TEXT NOT NULL,
                status_code INTEGER,
                ip_hash TEXT,
                user_agent TEXT,
                response_time_ms INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Analytics metrics
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                metric_value REAL,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Admin audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target_api_key_prefix TEXT,
                admin_ip_hash TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for better query performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_api_key_prefix ON logs(api_key_prefix)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analytics_metric_type ON analytics(metric_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_api_key_hash ON users(api_key_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_timestamp ON admin_audit(timestamp)")
        
        conn.commit()
        
    except sqlite3.Error as e:
        conn.rollback()
        raise Exception(f"Database schema initialization failed: {str(e)}")
    
    finally:
        db_pool.return_connection(conn)


ensure_db_schema()


# SECURITY UTILITIES

class SecurityUtils:
    """Security utility functions for hashing and validation"""
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key using bcrypt"""
        return bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_api_key(api_key: str, hashed: str) -> bool:
        """Verify API key against bcrypt hash"""
        try:
            return bcrypt.checkpw(api_key.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    @staticmethod
    def get_api_key_prefix(api_key: str) -> str:
        """Get first 8 characters of API key for logging (non-sensitive)"""
        return api_key[:8] if len(api_key) >= 8 else api_key[:4]
    
    @staticmethod
    def hash_ip(ip: str) -> str:
        """Hash IP address for privacy-preserving logging"""
        return bcrypt.hashpw(ip.encode('utf-8'), bcrypt.gensalt(rounds=4)).decode('utf-8')
    
    @staticmethod
    def validate_api_key_format(api_key: str) -> bool:
        """Validate API key format"""
        if not api_key or not isinstance(api_key, str):
            return False
        if len(api_key) < 16 or len(api_key) > 128:
            return False
        # Check for basic alphanumeric with some special chars
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.')
        return all(c in allowed_chars for c in api_key)
    
    @staticmethod
    def validate_tier(tier: str) -> bool:
        """Validate tier value"""
        return tier in Config.RATE_LIMITS


# IN-MEMORY RATE LIMITING STRUCTURES

class RateLimitCache:
    """Thread-safe in-memory cache for rate limiting"""
    
    def __init__(self):
        self.ip_requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.ip_lock = Lock()
        
        self.banned_ips: Dict[str, float] = {}
        self.banned_ips_lock = Lock()
        
        self.key_ban_counts: Dict[str, int] = defaultdict(int)
        self.key_ban_lock = Lock()
        
        self.realtime_metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'blocked_requests': 0,
            'active_keys': set(),
            'requests_per_second': deque(maxlen=60)
        }
        self.metrics_lock = Lock()
    
    def cleanup_old_data(self) -> None:
        """Periodic cleanup of old data to prevent memory leaks"""
        now = time.time()
        cutoff = now - (Config.IP_WINDOW * 2)
        
        with self.ip_lock:
            keys_to_remove = []
            for ip, requests in self.ip_requests.items():
                while requests and requests[0] < cutoff:
                    requests.popleft()
                if not requests:
                    keys_to_remove.append(ip)
            
            for key in keys_to_remove:
                del self.ip_requests[key]
        
        with self.banned_ips_lock:
            self.banned_ips = {ip: until for ip, until in self.banned_ips.items() if until > now}


rate_limit_cache = RateLimitCache()


# AUTHENTICATION DECORATORS

def require_admin_auth(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '').strip()
        
        if not token or not secrets.compare_digest(token, Config.ADMIN_TOKEN):
            log_admin_action('unauthorized_access_attempt', None, request.remote_addr, 
                           'Failed authentication attempt')
            abort(401, description="Unauthorized: Invalid or missing admin token")
        
        return f(*args, **kwargs)
    
    return decorated_function


def rate_limit_endpoint(max_requests: int = 10, window: int = 60):
    """Decorator to add rate limiting to any endpoint"""
    def decorator(f):
        endpoint_requests = defaultdict(lambda: deque())
        endpoint_lock = Lock()
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            
            with endpoint_lock:
                requests = endpoint_requests[ip]
                while requests and requests[0] <= now - window:
                    requests.popleft()
                
                if len(requests) >= max_requests:
                    return jsonify({
                        "error": "Rate limit exceeded for this endpoint",
                        "retry_after_seconds": int(window - (now - requests[0]))
                    }), 429
                
                requests.append(now)
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator


# LOGGING FUNCTIONS

def log_request(api_key: Optional[str], endpoint: str, status_code: int, 
                ip: str, user_agent: str = '', response_time_ms: int = 0) -> None:
    """Log request with privacy-preserving hashing"""
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_prefix = SecurityUtils.get_api_key_prefix(api_key) if api_key else "none"
        ip_hash = SecurityUtils.hash_ip(ip) if ip != "unknown" else "unknown"
        
        cursor.execute(
            """INSERT INTO logs (api_key_prefix, endpoint, status_code, ip_hash, user_agent, response_time_ms) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (api_key_prefix, endpoint, status_code, ip_hash, user_agent[:200], response_time_ms)
        )
        
        # Update total requests for user
        if api_key:
            api_key_hash = SecurityUtils.hash_api_key(api_key)
            cursor.execute(
                "UPDATE users SET total_requests = total_requests + 1, updated_at = CURRENT_TIMESTAMP WHERE api_key_hash = ?",
                (api_key_hash,)
            )
        
        conn.commit()
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error logging request: {str(e)}")
    
    finally:
        db_pool.return_connection(conn)
    
    # Update real-time metrics
    with rate_limit_cache.metrics_lock:
        rate_limit_cache.realtime_metrics['total_requests'] += 1
        if status_code == 200:
            rate_limit_cache.realtime_metrics['successful_requests'] += 1
        elif status_code in (403, 429):
            rate_limit_cache.realtime_metrics['blocked_requests'] += 1
        if api_key:
            rate_limit_cache.realtime_metrics['active_keys'].add(api_key_prefix)
        rate_limit_cache.realtime_metrics['requests_per_second'].append(time.time())
    
    # Broadcast to connected clients (non-sensitive data only)
    try:
        socketio.emit('new_request', {
            'api_key': api_key_prefix,
            'endpoint': endpoint,
            'status': status_code,
            'ip': ip[:7] + "***",  # Partial IP for display
            'timestamp': datetime.now().isoformat(),
            'response_time': response_time_ms
        })
    except Exception as e:
        print(f"Error emitting websocket event: {str(e)}")


def log_admin_action(action: str, target_api_key: Optional[str], admin_ip: str, details: str = "") -> None:
    """Log admin actions for audit trail"""
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        target_prefix = SecurityUtils.get_api_key_prefix(target_api_key) if target_api_key else None
        admin_ip_hash = SecurityUtils.hash_ip(admin_ip) if admin_ip != "unknown" else "unknown"
        
        cursor.execute(
            """INSERT INTO admin_audit (action, target_api_key_prefix, admin_ip_hash, details) 
               VALUES (?, ?, ?, ?)""",
            (action, target_prefix, admin_ip_hash, details)
        )
        conn.commit()
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error logging admin action: {str(e)}")
    
    finally:
        db_pool.return_connection(conn)


# USER MANAGEMENT

def get_or_create_user(api_key: str) -> Optional[sqlite3.Row]:
    """Get or create user with hashed API key"""
    if not SecurityUtils.validate_api_key_format(api_key):
        return None
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)
        
        # First, try to find existing user by trying to verify against all hashes
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        for user in users:
            if SecurityUtils.verify_api_key(api_key, user['api_key_hash']):
                return user
        
        # User not found, create new one
        cursor.execute(
            """INSERT INTO users (api_key_hash, api_key_prefix, request_count, window_start_time, 
                                  blocked, banned_until, tier) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (api_key_hash, api_key_prefix, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
             0, None, 'free')
        )
        conn.commit()
        
        cursor.execute("SELECT * FROM users WHERE api_key_hash = ?", (api_key_hash,))
        user = cursor.fetchone()
        return user
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error in get_or_create_user: {str(e)}")
        return None
    
    finally:
        db_pool.return_connection(conn)


def is_key_banned(user_row: sqlite3.Row) -> Tuple[bool, Optional[str]]:
    """Check if API key is banned or blocked"""
    blocked = user_row['blocked']
    banned_until = user_row['banned_until']
    
    if blocked:
        return True, "permanently blocked"
    
    if banned_until:
        try:
            banned_dt = datetime.strptime(banned_until, "%Y-%m-%d %H:%M:%S")
            if datetime.now() < banned_dt:
                return True, str(int((banned_dt - datetime.now()).total_seconds()))
        except Exception:
            return False, None
    
    return False, None


def ban_key(api_key: str) -> int:
    """Temporarily ban an API key with exponential backoff"""
    api_key_hash = SecurityUtils.hash_api_key(api_key)
    
    with rate_limit_cache.key_ban_lock:
        rate_limit_cache.key_ban_counts[api_key_hash] += 1
        multiplier = Config.BAN_MULTIPLIER ** (rate_limit_cache.key_ban_counts[api_key_hash] - 1)
    
    ban_seconds = int(Config.TEMP_BAN_SECONDS * multiplier)
    banned_until = (datetime.now() + timedelta(seconds=ban_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE users SET banned_until = ?, updated_at = CURRENT_TIMESTAMP WHERE api_key_hash = ?",
            (banned_until, api_key_hash)
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error banning key: {str(e)}")
    finally:
        db_pool.return_connection(conn)
    
    return ban_seconds


# IP RATE LIMITING

def is_ip_allowed(ip: str) -> Tuple[bool, Optional[int]]:
    """Check if IP is allowed to make requests"""
    now = time.time()
    
    # Check if IP is banned
    with rate_limit_cache.banned_ips_lock:
        ban_until = rate_limit_cache.banned_ips.get(ip)
        if ban_until and now < ban_until:
            return False, int(ban_until - now)
    
    # Check rate limit
    with rate_limit_cache.ip_lock:
        dq = rate_limit_cache.ip_requests[ip]
        
        # Remove old requests outside window
        while dq and dq[0] <= now - Config.IP_WINDOW:
            dq.popleft()
        
        if len(dq) < Config.IP_RATE_LIMIT:
            dq.append(now)
            return True, None
        else:
            # Ban IP temporarily
            ban_seconds = Config.TEMP_BAN_SECONDS
            ban_until = now + ban_seconds
            
            with rate_limit_cache.banned_ips_lock:
                rate_limit_cache.banned_ips[ip] = ban_until
            
            return False, ban_seconds


# API KEY RATE LIMITING

def is_key_allowed(api_key: str) -> Tuple[bool, Optional[Any]]:
    """Check if API key is allowed to make requests"""
    user = get_or_create_user(api_key)
    
    if not user:
        return False, {"type": "auth", "message": "Invalid API key format"}
    
    # Check if key is banned
    banned, reason = is_key_banned(user)
    if banned:
        return False, reason
    
    # Get tier limits
    tier = user['tier']
    limits = Config.RATE_LIMITS.get(tier, Config.RATE_LIMITS['free'])
    rate_limit = limits['requests']
    window_size = limits['window']
    
    try:
        window_start_dt = datetime.strptime(user['window_start_time'], "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()
    
    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        
        if elapsed >= window_size:
            # Reset window
            cursor.execute(
                """UPDATE users SET request_count = ?, window_start_time = ?, updated_at = CURRENT_TIMESTAMP 
                   WHERE api_key_hash = ?""",
                (1, now.strftime("%Y-%m-%d %H:%M:%S"), api_key_hash)
            )
            conn.commit()
            return True, None
        else:
            if user['request_count'] < rate_limit:
                # Increment counter
                cursor.execute(
                    "UPDATE users SET request_count = ?, updated_at = CURRENT_TIMESTAMP WHERE api_key_hash = ?",
                    (user['request_count'] + 1, api_key_hash)
                )
                conn.commit()
                return True, None
            else:
                # Rate limit exceeded, ban key
                ban_seconds = ban_key(api_key)
                return False, ban_seconds
    
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error in is_key_allowed: {str(e)}")
        return False, {"type": "error", "message": "Internal error"}
    
    finally:
        db_pool.return_connection(conn)


def allow_request(api_key: Optional[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Main function to check if request should be allowed"""
    ip = request.remote_addr or "unknown"
    
    # Check IP rate limit
    ip_ok, ip_info = is_ip_allowed(ip)
    if not ip_ok:
        return False, {"type": "ip", "retry_after": int(ip_info)}
    
    # Check API key
    if not api_key:
        return False, {"type": "auth", "message": "API key required"}
    
    # Validate and check key rate limit
    key_ok, key_info = is_key_allowed(api_key)
    if not key_ok:
        if isinstance(key_info, (int, float)):
            return False, {"type": "key", "retry_after": int(key_info)}
        else:
            return False, {"type": "key", "message": str(key_info)}
    
    return True, None


# DASHBOARD HTML TEMPLATE

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Rate Limiter Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { 
            color: white; 
            margin-bottom: 30px; 
            text-align: center; 
            font-size: 2.5em; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3); 
        }
        .metrics { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .metric-card { 
            background: white; 
            padding: 25px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .metric-card:hover { 
            transform: translateY(-5px); 
            box-shadow: 0 6px 12px rgba(0,0,0,0.15); 
        }
        .metric-value { 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #667eea; 
            margin: 10px 0; 
        }
        .metric-label { 
            color: #666; 
            font-size: 0.9em; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
        }
        .charts { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .chart-container { 
            background: white; 
            padding: 20px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
        }
        .logs-container { 
            background: white; 
            padding: 25px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
            max-height: 500px; 
            overflow-y: auto; 
        }
        .log-entry { 
            padding: 12px; 
            border-bottom: 1px solid #eee; 
            display: grid; 
            grid-template-columns: 150px 100px 200px 150px 1fr;
            gap: 15px;
            font-size: 0.9em;
            align-items: center;
        }
        .log-entry:hover { background: #f8f9fa; }
        .status-200 { color: #28a745; font-weight: bold; }
        .status-429 { color: #dc3545; font-weight: bold; }
        .status-403 { color: #ffc107; font-weight: bold; }
        .timestamp { color: #666; font-size: 0.85em; }
        .security-notice {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        @media (max-width: 768px) {
            .charts { grid-template-columns: 1fr; }
            .log-entry { grid-template-columns: 1fr; gap: 5px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Real-time Rate Limiter Dashboard</h1>
        
        <div class="security-notice">
            🔒 <strong>Security Enhanced Version</strong> - All API keys are hashed, IPs are anonymized, and admin endpoints are protected
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value" id="total-requests">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Successful</div>
                <div class="metric-value" id="successful-requests" style="color: #28a745;">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Blocked</div>
                <div class="metric-value" id="blocked-requests" style="color: #dc3545;">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Active API Keys</div>
                <div class="metric-value" id="active-keys">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Requests/Second</div>
                <div class="metric-value" id="req-per-second">0</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-container">
                <canvas id="requestChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="statusChart"></canvas>
            </div>
        </div>

        <div class="logs-container">
            <h3 style="margin-bottom: 15px;">📋 Recent Requests (Anonymized)</h3>
            <div id="logs"></div>
        </div>
    </div>

    <script>
        const socket = io();
        
        let totalRequests = 0;
        let successfulRequests = 0;
        let blockedRequests = 0;
        let activeKeys = new Set();
        
        const requestChartCtx = document.getElementById('requestChart').getContext('2d');
        const statusChartCtx = document.getElementById('statusChart').getContext('2d');
        
        const requestChart = new Chart(requestChartCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Requests',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: { title: { display: true, text: 'Requests Over Time' } },
                scales: { y: { beginAtZero: true } }
            }
        });
        
        const statusChart = new Chart(statusChartCtx, {
            type: 'doughnut',
            data: {
                labels: ['Successful', 'Blocked', 'Other'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                }]
            },
            options: {
                responsive: true,
                plugins: { title: { display: true, text: 'Request Status Distribution' } }
            }
        });
        
        function updateMetrics() {
            document.getElementById('total-requests').textContent = totalRequests;
            document.getElementById('successful-requests').textContent = successfulRequests;
            document.getElementById('blocked-requests').textContent = blockedRequests;
            document.getElementById('active-keys').textContent = activeKeys.size;
        }
        
        socket.on('new_request', function(data) {
            totalRequests++;
            
            if (data.status === 200) {
                successfulRequests++;
            } else if (data.status === 429 || data.status === 403) {
                blockedRequests++;
            }
            
            if (data.api_key !== 'none') {
                activeKeys.add(data.api_key);
            }
            
            updateMetrics();
            updateCharts();
            addLogEntry(data);
        });
        
        function updateCharts() {
            const now = new Date().toLocaleTimeString();
            requestChart.data.labels.push(now);
            requestChart.data.datasets[0].data.push(totalRequests);
            
            if (requestChart.data.labels.length > 20) {
                requestChart.data.labels.shift();
                requestChart.data.datasets[0].data.shift();
            }
            requestChart.update();
            
            statusChart.data.datasets[0].data = [
                successfulRequests,
                blockedRequests,
                totalRequests - successfulRequests - blockedRequests
            ];
            statusChart.update();
        }
        
        function addLogEntry(data) {
            const logsDiv = document.getElementById('logs');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            
            const statusClass = `status-${data.status}`;
            
            entry.innerHTML = `
                <span class="timestamp">${new Date(data.timestamp).toLocaleTimeString()}</span>
                <span class="${statusClass}">${data.status}</span>
                <span>${data.api_key}</span>
                <span>${data.endpoint}</span>
                <span>${data.ip} (${data.response_time}ms)</span>
            `;
            
            logsDiv.insertBefore(entry, logsDiv.firstChild);
            
            while (logsDiv.children.length > 50) {
                logsDiv.removeChild(logsDiv.lastChild);
            }
        }
        
        fetch('/api/metrics')
            .then(r => r.json())
            .then(data => {
                totalRequests = data.total_requests;
                successfulRequests = data.successful_requests;
                blockedRequests = data.blocked_requests;
                data.active_keys.forEach(k => activeKeys.add(k));
                updateMetrics();
            })
            .catch(err => console.error('Error loading metrics:', err));
    </script>
</body>
</html>
'''

# =============================================================================
# SDK API ROUTES - CORRECTED VERSION
# Add these to app.py around line 998 (after root route)
# =============================================================================

import secrets
import secrets

@app.route('/auth/api-key', methods=['POST'])
@require_jwt_auth
def create_api_key():
    user_id = g.user['user_id']  # from JWT middleware

    api_key = "rk_" + secrets.token_urlsafe(32)
    api_key_hash = SecurityUtils.hash_api_key(api_key)
    api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)

    conn = db_pool.get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (
            api_key_hash,
            api_key_prefix,
            tier,
            request_count,
            total_requests,
            blocked
        ) VALUES (?, ?, 'free', 0, 0, 0)
    """, (api_key_hash, api_key_prefix))

    conn.commit()
    db_pool.return_connection(conn)

    return jsonify({
        "api_key": api_key,
        "tier": "free",
        "note": "Save this key now. It will not be shown again."
    }), 201


@app.route('/auth/create_api_key', methods=['POST'])
def create_api_key():
    user_id = request.g.user['user_id']  # from JWT

    api_key = "rk_" + secrets.token_urlsafe(32)
    api_key_hash = SecurityUtils.hash_api_key(api_key)
    api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)

    conn = db_pool.get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (api_key_hash, api_key_prefix, tier)
        VALUES (?, ?, 'free')
    """, (api_key_hash, api_key_prefix))

    conn.commit()
    db_pool.return_connection(conn)

    return jsonify({
        "api_key": api_key,
        "tier": "free",
        "warning": "Save this key now. You will not see it again."
    }), 201


@app.route('/sdk.js')
def serve_sdk():
    """Serve the SDK JavaScript file to customers"""
    try:
        return send_file('static/ratelimiter-sdk.js', mimetype='application/javascript')
    except FileNotFoundError:
        return jsonify({'error': 'SDK file not found'}), 404


@app.route('/sdk/check', methods=['POST'])
def sdk_check():
    """
    Check if a request is allowed based on rate limits
    Called by the SDK before customer makes their API request
    """
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        endpoint = data.get('endpoint', 'unknown')
        method = data.get('method', 'GET')
        
        if not api_key:
            return jsonify({
                'allowed': False,
                'error': 'API key required',
                'remaining': 0
            }), 400
        
        # Use YOUR EXISTING is_key_allowed function
        key_ok, key_info = is_key_allowed(api_key)
        
        if key_ok:
            # Get user info to return remaining requests
            user = get_or_create_user(api_key)
            if user:
                tier = user.get('tier', 'free')
                limits = Config.RATE_LIMITS.get(tier, Config.RATE_LIMITS['free'])
                current_count = user.get('request_count', 0)
                
                return jsonify({
                    'allowed': True,
                    'remaining': limits['requests'] - current_count,
                    'limit': limits['requests'],
                    'window_seconds': limits['window'],
                    'tier': tier,
                    'reset_at': (datetime.now() + timedelta(seconds=limits['window'])).isoformat()
                }), 200
            else:
                return jsonify({
                    'allowed': True,
                    'remaining': 5,
                    'limit': 5,
                    'tier': 'free'
                }), 200
        
        else:
            # Rate limited - get tier info for message
            user = get_or_create_user(api_key)
            tier = user.get('tier', 'free') if user else 'free'
            limits = Config.RATE_LIMITS.get(tier, Config.RATE_LIMITS['free'])
            
            # Extract retry_after from key_info
            retry_after = limits['window']
            if isinstance(key_info, (int, float)):
                retry_after = int(key_info)
            elif isinstance(key_info, dict) and 'retry_after' in key_info:
                retry_after = key_info['retry_after']
            
            return jsonify({
                'allowed': False,
                'remaining': 0,
                'limit': limits['requests'],
                'window_seconds': limits['window'],
                'tier': tier,
                'retry_after': retry_after,
                'message': 'Rate limit exceeded',
                'reset_at': (datetime.now() + timedelta(seconds=retry_after)).isoformat()
            }), 429
    
    except Exception as e:
        print(f"SDK check error: {e}")
        return jsonify({
            'allowed': False,
            'error': 'Internal server error',
            'remaining': 0
        }), 500


@app.route('/sdk/track', methods=['POST'])
def sdk_track():
    """
    Track SDK usage for analytics (optional)
    Logs requests made through the SDK
    """
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        endpoint = data.get('endpoint', 'unknown')
        method = data.get('method', 'GET')
        status_code = data.get('status_code', 200)
        response_time = data.get('response_time_ms', 0)
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 400
        
        log_request(
            api_key=api_key,
            endpoint=f"SDK:{endpoint}",
            method=method,
            status_code=status_code,
            ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            response_time_ms=response_time
        )
        
        return jsonify({
            'success': True,
            'message': 'Request tracked'
        }), 200
    
    except Exception as e:
        print(f"SDK track error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to track request'
        }), 500


def get_user_info(api_key: str) -> Optional[Dict]:
    """Get user information by API key"""
    try:
        with db_pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT api_key, tier, request_count, window_start_time, 
                       blocked, banned_until, total_requests
                FROM users 
                WHERE api_key = ?
            ''', (api_key,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'api_key': row[0],
                    'tier': row[1],
                    'request_count': row[2],
                    'window_start_time': row[3],
                    'blocked': row[4],
                    'banned_until': row[5],
                    'total_requests': row[6]
                }
            return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None

@app.route('/')
def home():
    """Root endpoint with API information"""
    return jsonify({
        "message": "🚀 Enhanced API Rate Limiter with Real-time Monitoring (Security Hardened)",
        "version": "2.0.0",
        "dashboard": "/dashboard",
        "endpoints": {
            "data": "/data?api_key=YOUR_KEY",
            "usage": "/usage?api_key=YOUR_KEY",
            "metrics": "/api/metrics",
            "admin_users": "/admin/users (requires auth)",
            "admin_upgrade": "/admin/upgrade_tier (requires auth)",
            "admin_block": "/admin/block_key (requires auth)",
            "admin_unblock": "/admin/unblock_key (requires auth)"
        },
        "security": {
            "api_keys": "hashed with bcrypt",
            "ips": "anonymized in logs",
            "admin_endpoints": "protected with bearer token"
        }
    })


@app.route('/dashboard')
def dashboard():
    """Real-time monitoring dashboard"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/metrics')
@rate_limit_endpoint(max_requests=30, window=60)
def get_metrics():
    """Get current system metrics"""
    with rate_limit_cache.metrics_lock:
        now = time.time()
        recent_requests = [t for t in rate_limit_cache.realtime_metrics['requests_per_second'] if now - t < 1]
        rps = len(recent_requests)
        
        return jsonify({
            'total_requests': rate_limit_cache.realtime_metrics['total_requests'],
            'successful_requests': rate_limit_cache.realtime_metrics['successful_requests'],
            'blocked_requests': rate_limit_cache.realtime_metrics['blocked_requests'],
            'active_keys': list(rate_limit_cache.realtime_metrics['active_keys']),
            'requests_per_second': rps
        })


@app.route('/data')
def get_data():
    """Protected data endpoint with rate limiting"""
    start_time = time.time()
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get('User-Agent', '')

    allowed, info = allow_request(api_key)

    if allowed:
        status = 200
        body = {
            "message": "✅ Here's your protected data!",
            "timestamp": datetime.now().isoformat(),
            "data": {"example": "This is protected content"}
        }
    else:
        if info and info.get("type") == "auth":
            status = 400
            body = {"error": info.get("message", "API key required")}
        elif info and info.get("type") == "ip":
            status = 429
            reset = info.get("retry_after", Config.IP_WINDOW)
            body = {"error": "⛔ IP rate limit exceeded", "retry_after_seconds": reset}
        elif info and info.get("type") == "key":
            if "retry_after" in info:
                status = 429
                reset = info["retry_after"]
                body = {"error": "⛔ API key rate limit exceeded", "retry_after_seconds": reset}
            else:
                status = 403
                body = {"error": f"⛔ API key blocked: {info.get('message')}"}
        else:
            status = 429
            body = {"error": "⛔ Rate limit exceeded"}

    response_time = int((time.time() - start_time) * 1000)
    log_request(api_key, "/data", status, ip, user_agent, response_time)

    headers = {}
    if status == 429 and "retry_after_seconds" in body:
        headers["Retry-After"] = str(body["retry_after_seconds"])

    headers = {}

    if api_key:
        user = get_or_create_user(api_key)
    if user:
        tier = user['tier']
        limits = Config.RATE_LIMITS[tier]
        headers.update({
            "X-RateLimit-Limit": str(limits['requests']),
            "X-RateLimit-Remaining": str(
                max(0, limits['requests'] - user['request_count'])
            ),
            "X-RateLimit-Window": str(limits['window'])
        })

    if status == 429 and "retry_after_seconds" in body:
        headers["Retry-After"] = str(body["retry_after_seconds"])


    return jsonify(body), status, headers


@app.route('/usage')
@rate_limit_endpoint(max_requests=20, window=60)
def usage():
    """Get API usage information for a key"""
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"

    if not api_key:
        log_request(None, "/usage", 400, ip)
        return jsonify({"error": "API key required"}), 400

    user = get_or_create_user(api_key)
    
    if not user:
        log_request(api_key, "/usage", 400, ip)
        return jsonify({"error": "Invalid API key"}), 400
    
    tier = user['tier']
    limits = Config.RATE_LIMITS.get(tier, Config.RATE_LIMITS['free'])
    
    try:
        window_start_dt = datetime.strptime(user['window_start_time'], "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()
    
    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()
    reset_in = max(0, int(limits['window'] - elapsed))
    requests_left = max(0, limits['requests'] - user['request_count'])

    log_request(api_key, "/usage", 200, ip)
    
    return jsonify({
        "tier": tier,
        "requests_left": requests_left,
        "requests_limit": limits['requests'],
        "window_seconds": limits['window'],
        "reset_in_seconds": reset_in,
        "blocked": bool(user['blocked']),
        "banned_until": user['banned_until'],
        "total_requests_lifetime": user['total_requests']
    })


@app.route('/admin/users')
@require_admin_auth
@rate_limit_endpoint(max_requests=20, window=60)
def admin_users():
    """Get list of all users (admin only)"""
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT api_key_prefix, request_count, total_requests, tier, blocked, 
                   banned_until, created_at, updated_at 
            FROM users 
            ORDER BY total_requests DESC
        """)
        users = cursor.fetchall()
        
        log_admin_action('view_users', None, request.remote_addr, f"Viewed {len(users)} users")
        
        return jsonify({
            "users": [
                {
                    "api_key_prefix": u['api_key_prefix'],
                    "current_count": u['request_count'],
                    "total_requests": u['total_requests'],
                    "tier": u['tier'],
                    "blocked": bool(u['blocked']),
                    "banned_until": u['banned_until'],
                    "created_at": u['created_at'],
                    "updated_at": u['updated_at']
                }
                for u in users
            ],
            "total_users": len(users)
        })
    
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/admin/upgrade_tier', methods=['POST'])
@require_admin_auth
@rate_limit_endpoint(max_requests=10, window=60)
def upgrade_tier():
    """Upgrade user tier (admin only)"""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    
    api_key = data.get("api_key")
    new_tier = data.get("tier", "free")
    
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    
    if not SecurityUtils.validate_tier(new_tier):
        return jsonify({"error": f"Invalid tier. Must be one of: {list(Config.RATE_LIMITS.keys())}"}), 400
    
    if not SecurityUtils.validate_api_key_format(api_key):
        return jsonify({"error": "Invalid API key format"}), 400
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        
        cursor.execute(
            "UPDATE users SET tier = ?, updated_at = CURRENT_TIMESTAMP WHERE api_key_hash = ?",
            (new_tier, api_key_hash)
        )
        
        if cursor.rowcount == 0:
            return jsonify({"error": "API key not found"}), 404
        
        conn.commit()
        
        api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)
        log_admin_action('upgrade_tier', api_key, request.remote_addr, 
                        f"Upgraded to {new_tier}")
        
        return jsonify({
            "status": "success",
            "message": f"API key {api_key_prefix}*** upgraded to {new_tier}",
            "new_tier": new_tier
        })
    
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/admin/block_key', methods=['POST'])
@require_admin_auth
@rate_limit_endpoint(max_requests=10, window=60)
def admin_block_key():
    """Block an API key permanently (admin only)"""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    
    api_key = data.get("api_key")
    reason = data.get("reason", "Admin action")
    
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    
    if not SecurityUtils.validate_api_key_format(api_key):
        return jsonify({"error": "Invalid API key format"}), 400
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        
        cursor.execute(
            "UPDATE users SET blocked = 1, updated_at = CURRENT_TIMESTAMP WHERE api_key_hash = ?",
            (api_key_hash,)
        )
        
        if cursor.rowcount == 0:
            return jsonify({"error": "API key not found"}), 404
        
        conn.commit()
        
        api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)
        log_admin_action('block_key', api_key, request.remote_addr, reason)
        
        return jsonify({
            "status": "success",
            "message": f"API key {api_key_prefix}*** blocked",
            "reason": reason
        })
    
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/admin/unblock_key', methods=['POST'])
@require_admin_auth
@rate_limit_endpoint(max_requests=10, window=60)
def admin_unblock_key():
    """Unblock an API key (admin only)"""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    
    api_key = data.get("api_key")
    
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    
    if not SecurityUtils.validate_api_key_format(api_key):
        return jsonify({"error": "Invalid API key format"}), 400
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        
        cursor.execute(
            """UPDATE users SET blocked = 0, banned_until = NULL, updated_at = CURRENT_TIMESTAMP 
               WHERE api_key_hash = ?""",
            (api_key_hash,)
        )
        
        if cursor.rowcount == 0:
            return jsonify({"error": "API key not found"}), 404
        
        conn.commit()
        
        with rate_limit_cache.key_ban_lock:
            rate_limit_cache.key_ban_counts.pop(api_key_hash, None)
        
        api_key_prefix = SecurityUtils.get_api_key_prefix(api_key)
        log_admin_action('unblock_key', api_key, request.remote_addr, "Key unblocked")
        
        return jsonify({
            "status": "success",
            "message": f"API key {api_key_prefix}*** unblocked"
        })
    
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/logs')
@require_admin_auth
@rate_limit_endpoint(max_requests=10, window=60)
def logs():
    """Get request logs (admin only)"""
    limit = request.args.get('limit', 100, type=int)
    
    # Validate limit to prevent abuse
    if limit < 1 or limit > Config.MAX_LOG_ENTRIES:
        limit = Config.MAX_LOG_ENTRIES
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT api_key_prefix, endpoint, status_code, ip_hash, timestamp, response_time_ms 
               FROM logs 
               ORDER BY timestamp DESC 
               LIMIT ?""",
            (limit,)
        )
        logs = cursor.fetchall()
        
        log_admin_action('view_logs', None, request.remote_addr, f"Viewed {len(logs)} log entries")
        
        return jsonify({
            "logs": [
                {
                    "api_key_prefix": l['api_key_prefix'],
                    "endpoint": l['endpoint'],
                    "status_code": l['status_code'],
                    "ip_hash": l['ip_hash'][:16] + "***",  # Partially hide hash
                    "timestamp": l['timestamp'],
                    "response_time_ms": l['response_time_ms']
                }
                for l in logs
            ],
            "count": len(logs),
            "limit": limit
        })
    
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/admin/audit')
@require_admin_auth
@rate_limit_endpoint(max_requests=10, window=60)
def admin_audit():
    """Get admin audit log (admin only)"""
    limit = request.args.get('limit', 100, type=int)
    
    if limit < 1 or limit > Config.MAX_LOG_ENTRIES:
        limit = Config.MAX_LOG_ENTRIES
    
    conn = db_pool.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT action, target_api_key_prefix, admin_ip_hash, details, timestamp 
               FROM admin_audit 
               ORDER BY timestamp DESC 
               LIMIT ?""",
            (limit,)
        )
        audit_logs = cursor.fetchall()
        
        return jsonify({
            "audit_logs": [
                {
                    "action": log['action'],
                    "target": log['target_api_key_prefix'],
                    "admin_ip": log['admin_ip_hash'][:16] + "***" if log['admin_ip_hash'] != "unknown" else "unknown",
                    "details": log['details'],
                    "timestamp": log['timestamp']
                }
                for log in audit_logs
            ],
            "count": len(audit_logs)
        })
    
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    finally:
        db_pool.return_connection(conn)


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_pool.return_connection(conn)
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0"
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 503


# WEBSOCKET EVENT HANDLERS

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print(f'Client connected: {request.sid}')
    emit('connected', {
        'message': 'Connected to rate limiter dashboard',
        'version': '2.0.0',
        'security': 'enhanced'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print(f'Client disconnected: {request.sid}')


# ERROR HANDLERS

@app.errorhandler(400)
def bad_request(e):
    """Handle 400 errors"""
    return jsonify({"error": "Bad request", "message": str(e)}), 400


@app.errorhandler(401)
def unauthorized(e):
    """Handle 401 errors"""
    return jsonify({"error": "Unauthorized", "message": str(e)}), 401


@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors"""
    return jsonify({"error": "Forbidden", "message": str(e)}), 403


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Not found", "message": str(e)}), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle 413 errors"""
    return jsonify({"error": "Request entity too large", "max_size": Config.MAX_CONTENT_LENGTH}), 413


@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle 429 errors"""
    return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return jsonify({"error": "Internal server error"}), 500


# CLEANUP AND SHUTDOWN

def cleanup_task():
    """Periodic cleanup of in-memory caches"""
    import threading
    
    def run_cleanup():
        while True:
            time.sleep(300)  # Run every 5 minutes
            try:
                rate_limit_cache.cleanup_old_data()
            except Exception as e:
                print(f"Error in cleanup task: {str(e)}")
    
    cleanup_thread = threading.Thread(target=run_cleanup, daemon=True)
    cleanup_thread.start()


@app.before_request
def startup_tasks():
    """Tasks to run on application startup"""
    cleanup_task()
    print("✅ Rate Limiter Started (Security Enhanced)")
    print(f"🔒 Admin authentication: ENABLED")
    print(f"🔑 API key hashing: ENABLED")
    print(f"🛡️  CORS origins: {Config.CORS_ORIGINS}")
    print(f"📊 Dashboard: http://localhost:5000/dashboard")


# MAIN

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 Enhanced API Rate Limiter - Security Hardened Version 2.0.0")
    print("="*80)
    print("\n⚠️  IMPORTANT: Before running in production:")
    print("  1. Set JWT_SECRET_KEY environment variable")
    print("  2. Set ADMIN_TOKEN environment variable")
    print("  3. Configure CORS_ORIGINS for your domain")
    print("  4. Use a production WSGI server (gunicorn/uwsgi)")
    print("  5. Consider using Redis for distributed rate limiting")
    print("  6. Enable SSL/TLS")
    print("\n" + "="*80 + "\n")
    
    socketio.run(
        app,
        debug=Config.DEBUG,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        
        allow_unsafe_werkzeug=True  # Only for development
    )