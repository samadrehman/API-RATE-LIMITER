"""
Mock Backend Servers for Load Balancer Testing

PURPOSE:
This module creates multiple Flask-based HTTP backend servers for testing and demonstrating
load balancer functionality. It simulates realistic backend behavior with:
- Health check endpoints for load balancer monitoring
- Variable response times to test different routing strategies
- Request counting and statistics for performance analysis
- Multiple configurable server instances with different characteristics
- Thread-safe request handling for concurrent connections

ARCHITECTURE:
- create_backend_app(): Factory function creating configured Flask applications
- run_backend(): Thread worker running individual backend server instances
- main(): Orchestrates multiple backend servers with staggered startup

SECURITY CONSIDERATIONS:
- Input validation on all request parameters
- Protection against path traversal attacks
- Rate limiting support to prevent abuse
- Safe error handling without information disclosure
- Thread-safe statistics tracking
- Proper logging for security monitoring
- Protection against common web vulnerabilities (XSS, injection, etc.)

USAGE:
Run this script to start 3 backend servers on ports 5001-5003 with different
response characteristics. These backends are designed to work with the load
balancer for testing various routing strategies and failure scenarios.
"""

from flask import Flask, jsonify, request, abort
import time
import random
import sys
import re
import logging
from threading import Thread, Lock
from typing import Dict, Any, Optional
from functools import wraps
import secrets

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter to prevent abuse"""
    
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
        self.lock = Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is within rate limit"""
        now = time.time()
        
        with self.lock:
            if identifier not in self.requests:
                self.requests[identifier] = []
            
            request_times = self.requests[identifier]
            request_times[:] = [t for t in request_times if now - t < self.window_seconds]
            
            if len(request_times) >= self.max_requests:
                return False
            
            request_times.append(now)
            
            if len(self.requests) > 10000:
                oldest_key = min(self.requests.keys(), 
                               key=lambda k: min(self.requests[k]) if self.requests[k] else now)
                del self.requests[oldest_key]
            
            return True


def validate_endpoint_path(path: str) -> bool:
    """Validate endpoint path to prevent path traversal"""
    if not path or not isinstance(path, str):
        return False
    
    if len(path) > 256:
        return False
    
    dangerous_patterns = [
        r'\.\.',
        r'[<>]',
        r'[\x00-\x1f\x7f]',
        r'[;&|`$()]',
        r'\\',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, path):
            return False
    
    if not re.match(r'^[a-zA-Z0-9/_-]+$', path):
        return False
    
    return True


def sanitize_string(value: str, max_length: int = 256) -> str:
    """Sanitize string input"""
    if not isinstance(value, str):
        return "invalid"
    
    value = value[:max_length]
    value = re.sub(r'[<>&"\']', '', value)
    
    return value


def validate_api_key(api_key: str) -> bool:
    """Validate API key format"""
    if not api_key or not isinstance(api_key, str):
        return False
    
    if len(api_key) < 8 or len(api_key) > 128:
        return False
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', api_key):
        return False
    
    return True


def require_rate_limit(rate_limiter: RateLimiter):
    """Decorator to enforce rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr or 'unknown'
            
            if not rate_limiter.is_allowed(client_ip):
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': 'Too many requests. Please try again later.'
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def create_backend_app(port: int, name: str, response_delay: float = 0.0):
    """Create a Flask app simulating a backend server"""
    
    if not isinstance(port, int) or not (1024 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}")
    
    if not isinstance(name, str) or not name:
        raise ValueError("Name must be a non-empty string")
    
    if response_delay < 0 or response_delay > 10:
        raise ValueError(f"Response delay must be between 0 and 10 seconds")
    
    name = sanitize_string(name, max_length=64)
    
    app = Flask(name)
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
    
    stats = {
        'requests_served': 0,
        'uptime_start': time.time(),
        'failed_requests': 0,
        'total_response_time': 0.0
    }
    stats_lock = Lock()
    
    rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(413)
    def request_too_large(e):
        return jsonify({'error': 'Request too large'}), 413
    
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal error: {type(e).__name__}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/health')
    def health():
        """Health check endpoint"""
        try:
            with stats_lock:
                uptime = round(time.time() - stats['uptime_start'], 2)
                requests_served = stats['requests_served']
            
            return jsonify({
                'status': 'healthy',
                'server': name,
                'port': port,
                'uptime': uptime,
                'requests_served': requests_served
            }), 200
        except Exception as e:
            logger.error(f"Health check error: {type(e).__name__}")
            return jsonify({'status': 'unhealthy'}), 500
    
    @app.route('/data')
    @require_rate_limit(rate_limiter)
    def get_data():
        """Main data endpoint"""
        start_time = time.time()
        
        try:
            delay = response_delay + random.uniform(0.01, 0.05)
            if delay > 0:
                time.sleep(min(delay, 5.0))
            
            api_key = request.args.get('api_key', '')
            
            if api_key and not validate_api_key(api_key):
                logger.warning(f"Invalid API key format from {request.remote_addr}")
                return jsonify({'error': 'Invalid API key format'}), 400
            
            api_key = sanitize_string(api_key, max_length=128) if api_key else 'none'
            
            with stats_lock:
                stats['requests_served'] += 1
                request_count = stats['requests_served']
                stats['total_response_time'] += (time.time() - start_time)
            
            return jsonify({
                'message': f'Data from {name}',
                'server': name,
                'port': port,
                'api_key_provided': bool(api_key and api_key != 'none'),
                'timestamp': int(time.time()),
                'request_count': request_count
            }), 200
            
        except Exception as e:
            logger.error(f"Error in get_data: {type(e).__name__}")
            with stats_lock:
                stats['failed_requests'] += 1
            return jsonify({'error': 'Internal error'}), 500
    
    @app.route('/api/<path:endpoint>')
    @require_rate_limit(rate_limiter)
    def api_endpoint(endpoint):
        """Generic API endpoint"""
        start_time = time.time()
        
        try:
            if not validate_endpoint_path(endpoint):
                logger.warning(f"Invalid endpoint path: {endpoint}")
                return jsonify({'error': 'Invalid endpoint path'}), 400
            
            endpoint = sanitize_string(endpoint, max_length=256)
            
            delay = response_delay + random.uniform(0.01, 0.03)
            if delay > 0:
                time.sleep(min(delay, 5.0))
            
            params = {}
            for key, value in request.args.items():
                if len(params) >= 20:
                    break
                safe_key = sanitize_string(key, max_length=64)
                safe_value = sanitize_string(value, max_length=256)
                params[safe_key] = safe_value
            
            with stats_lock:
                stats['requests_served'] += 1
                stats['total_response_time'] += (time.time() - start_time)
            
            return jsonify({
                'endpoint': endpoint,
                'server': name,
                'port': port,
                'method': request.method,
                'params': params,
                'param_count': len(request.args)
            }), 200
            
        except Exception as e:
            logger.error(f"Error in api_endpoint: {type(e).__name__}")
            with stats_lock:
                stats['failed_requests'] += 1
            return jsonify({'error': 'Internal error'}), 500
    
    @app.route('/slow')
    @require_rate_limit(rate_limiter)
    def slow_endpoint():
        """Intentionally slow endpoint"""
        try:
            delay = 2 + random.uniform(0, 1)
            time.sleep(min(delay, 10.0))
            
            with stats_lock:
                stats['requests_served'] += 1
            
            return jsonify({
                'message': 'This was a slow request',
                'server': name,
                'delay_seconds': round(delay, 2)
            }), 200
            
        except Exception as e:
            logger.error(f"Error in slow_endpoint: {type(e).__name__}")
            with stats_lock:
                stats['failed_requests'] += 1
            return jsonify({'error': 'Internal error'}), 500
    
    @app.route('/stats')
    def server_stats():
        """Server statistics"""
        try:
            with stats_lock:
                uptime = round(time.time() - stats['uptime_start'], 2)
                requests_served = stats['requests_served']
                failed_requests = stats['failed_requests']
                avg_response_time = (
                    round(stats['total_response_time'] / max(requests_served, 1) * 1000, 2)
                    if requests_served > 0 else 0
                )
            
            return jsonify({
                'server': name,
                'port': port,
                'requests_served': requests_served,
                'failed_requests': failed_requests,
                'uptime_seconds': uptime,
                'avg_response_time_ms': avg_response_time
            }), 200
            
        except Exception as e:
            logger.error(f"Error in server_stats: {type(e).__name__}")
            return jsonify({'error': 'Internal error'}), 500
    
    @app.route('/')
    def root():
        """Root endpoint"""
        try:
            return jsonify({
                'message': f'Backend server: {name}',
                'port': port,
                'endpoints': ['/health', '/data', '/api/<endpoint>', '/slow', '/stats'],
                'version': '1.0.0'
            }), 200
            
        except Exception as e:
            logger.error(f"Error in root: {type(e).__name__}")
            return jsonify({'error': 'Internal error'}), 500
    
    @app.before_request
    def log_request():
        """Log incoming requests"""
        if request.path != '/health':
            logger.info(f"{request.method} {request.path} from {request.remote_addr}")
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Type'] = 'application/json'
        return response
    
    return app


def run_backend(port: int, name: str, response_delay: float = 0.0):
    """Run a backend server"""
    try:
        app = create_backend_app(port, name, response_delay)
        logger.info(f"Starting {name} on port {port} (delay: {response_delay}s)")
        
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    except ValueError as e:
        logger.error(f"Configuration error for {name}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start {name}: {type(e).__name__}: {e}")
        sys.exit(1)


def main():
    """Start multiple backend servers"""
    print("="*60)
    print("🎯 Starting Mock Backend Servers")
    print("="*60)
    
    backends = [
        (5001, "Backend-Fast", 0.01),
        (5002, "Backend-Medium", 0.05),
        (5003, "Backend-Slow", 0.1),
    ]
    
    for port, name, delay in backends:
        if not (1024 <= port <= 65535):
            logger.error(f"Invalid port {port} for {name}")
            sys.exit(1)
        
        if delay < 0 or delay > 10:
            logger.error(f"Invalid delay {delay} for {name}")
            sys.exit(1)
    
    threads = []
    for port, name, delay in backends:
        thread = Thread(target=run_backend, args=(port, name, delay))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        time.sleep(0.5)
    
    print("\n" + "="*60)
    print("✅ All backend servers running!")
    print("="*60)
    print("\nBackend URLs:")
    for port, name, delay in backends:
        print(f"  • http://localhost:{port} ({name}, ~{delay}s delay)")
    
    print("\n💡 Now start the load balancer:")
    print("   python load_balancer.py")
    print("\n🌐 Then access: http://localhost:8080/dashboard")
    print("\n⚠️  Press Ctrl+C to stop all servers")
    print("="*60 + "\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down backend servers...")
        logger.info("Received shutdown signal")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"Fatal error: {type(e).__name__}: {e}")
        sys.exit(1)