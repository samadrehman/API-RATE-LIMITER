from flask import Flask, jsonify, request
import time
import random
import sys
from threading import Thread

def create_backend_app(port, name, response_delay=0.0):
    """Create a Flask app simulating a backend server"""
    app = Flask(name)
    
    stats = {
        'requests_served': 0,
        'uptime_start': time.time()
    }
    
    @app.route('/health')
    def health():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'server': name,
            'port': port,
            'uptime': round(time.time() - stats['uptime_start'], 2)
        })
    
    @app.route('/data')
    def get_data():
        """Main data endpoint"""
        # Simulate processing time
        time.sleep(response_delay + random.uniform(0.01, 0.05))
        
        stats['requests_served'] += 1
        
        api_key = request.args.get('api_key', 'unknown')
        
        return jsonify({
            'message': f'✅ Data from {name}',
            'server': name,
            'port': port,
            'api_key': api_key,
            'timestamp': time.time(),
            'request_count': stats['requests_served']
        })
    
    @app.route('/api/<path:endpoint>')
    def api_endpoint(endpoint):
        """Generic API endpoint"""
        time.sleep(response_delay + random.uniform(0.01, 0.03))
        
        stats['requests_served'] += 1
        
        return jsonify({
            'endpoint': endpoint,
            'server': name,
            'port': port,
            'method': request.method,
            'params': dict(request.args)
        })
    
    @app.route('/slow')
    def slow_endpoint():
        """Intentionally slow endpoint"""
        time.sleep(2 + random.uniform(0, 1))
        return jsonify({
            'message': 'This was a slow request',
            'server': name
        })
    
    @app.route('/stats')
    def server_stats():
        """Server statistics"""
        return jsonify({
            'server': name,
            'port': port,
            'requests_served': stats['requests_served'],
            'uptime_seconds': round(time.time() - stats['uptime_start'], 2)
        })
    
    @app.route('/')
    def root():
        """Root endpoint"""
        return jsonify({
            'message': f'Backend server: {name}',
            'port': port,
            'endpoints': ['/health', '/data', '/api/<endpoint>', '/slow', '/stats']
        })
    
    return app


def run_backend(port, name, response_delay=0.0):
    """Run a backend server"""
    app = create_backend_app(port, name, response_delay)
    print(f"🚀 Starting {name} on port {port} (delay: {response_delay}s)")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)


def main():
    """Start multiple backend servers"""
    print("="*60)
    print("🎯 Starting Mock Backend Servers")
    print("="*60)
    
    # Configuration for 3 backend servers with different characteristics
    backends = [
        (5001, "Backend-Fast", 0.01),      # Fast server
        (5002, "Backend-Medium", 0.05),    # Medium speed server
        (5003, "Backend-Slow", 0.1),       # Slower server
    ]
    
    threads = []
    for port, name, delay in backends:
        thread = Thread(target=run_backend, args=(port, name, delay))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        time.sleep(0.5)  # Stagger startup
    
    print("\n" + "="*60)
    print("✅ All backend servers running!")
    print("="*60)
    print("\nBackend URLs:")
    for port, name, delay in backends:
        print(f"  • http://localhost:{port} ({name}, ~{delay}s delay)")
    
    print("\n💡 Now start the load balancer:")
    print("   python load_balancer.py")
    print("\n🌐 Then access: http://localhost:8080/dashboard")
    print("="*60 + "\n")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down backend servers...")
        sys.exit(0)


if __name__ == '__main__':
    main()