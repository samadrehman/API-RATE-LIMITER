import asyncio
import aiohttp
from aiohttp import web
import time
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict
import json
from datetime import datetime
import hashlib

# ============================================================================
# LOAD BALANCER WITH ADVANCED BACKEND TRICKS
# ============================================================================

@dataclass
class BackendServer:
    """Represents a backend server instance"""
    host: str
    port: int
    weight: int = 1
    healthy: bool = True
    active_connections: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    last_health_check: float = 0.0
    
    @property
    def url(self):
        return f"http://{self.host}:{self.port}"
    
    @property
    def load_score(self):
        """Calculate load score (lower is better)"""
        # Factor in connections, response time, and failure rate
        failure_penalty = (self.failed_requests / max(self.total_requests, 1)) * 100
        return self.active_connections + (self.avg_response_time / 10) + failure_penalty


class LoadBalancer:
    """Advanced load balancer with multiple strategies"""
    
    def __init__(self):
        self.backends: List[BackendServer] = []
        self.strategy = "least_connections"  # round_robin, least_connections, weighted, ip_hash
        self.current_index = 0
        self.health_check_interval = 10  # seconds
        self.circuit_breaker_threshold = 5  # consecutive failures
        self.circuit_breaker_timeout = 30  # seconds
        self.sticky_sessions: Dict[str, BackendServer] = {}
        self.request_history = deque(maxlen=1000)
        
    def add_backend(self, host: str, port: int, weight: int = 1):
        """Add a backend server"""
        backend = BackendServer(host=host, port=port, weight=weight)
        self.backends.append(backend)
        print(f"✅ Added backend: {backend.url} (weight: {weight})")
    
    def round_robin(self) -> BackendServer:
        """Round-robin load balancing"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        backend = healthy_backends[self.current_index % len(healthy_backends)]
        self.current_index += 1
        return backend
    
    def least_connections(self) -> BackendServer:
        """Least connections load balancing"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        return min(healthy_backends, key=lambda b: b.active_connections)
    
    def weighted_round_robin(self) -> BackendServer:
        """Weighted round-robin (servers with higher weight get more traffic)"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        # Create weighted list
        weighted_list = []
        for backend in healthy_backends:
            weighted_list.extend([backend] * backend.weight)
        
        backend = weighted_list[self.current_index % len(weighted_list)]
        self.current_index += 1
        return backend
    
    def ip_hash(self, client_ip: str) -> BackendServer:
        """IP hash - same client always goes to same backend (sticky sessions)"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        # Hash the IP and use modulo to select backend
        hash_value = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
        index = hash_value % len(healthy_backends)
        return healthy_backends[index]
    
    def least_response_time(self) -> BackendServer:
        """Select backend with lowest average response time"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        return min(healthy_backends, key=lambda b: b.avg_response_time)
    
    def adaptive(self) -> BackendServer:
        """Adaptive load balancing - considers multiple factors"""
        healthy_backends = [b for b in self.backends if b.healthy]
        if not healthy_backends:
            raise Exception("No healthy backends available")
        
        return min(healthy_backends, key=lambda b: b.load_score)
    
    def select_backend(self, client_ip: str = None, session_id: str = None) -> BackendServer:
        """Select backend based on configured strategy"""
        # Check sticky session first
        if session_id and session_id in self.sticky_sessions:
            backend = self.sticky_sessions[session_id]
            if backend.healthy:
                return backend
        
        # Select based on strategy
        if self.strategy == "round_robin":
            backend = self.round_robin()
        elif self.strategy == "least_connections":
            backend = self.least_connections()
        elif self.strategy == "weighted":
            backend = self.weighted_round_robin()
        elif self.strategy == "ip_hash":
            backend = self.ip_hash(client_ip or "default")
        elif self.strategy == "least_response_time":
            backend = self.least_response_time()
        elif self.strategy == "adaptive":
            backend = self.adaptive()
        else:
            backend = self.least_connections()
        
        # Store sticky session
        if session_id:
            self.sticky_sessions[session_id] = backend
        
        return backend
    
    async def health_check(self):
        """Periodically check backend health"""
        while True:
            await asyncio.sleep(self.health_check_interval)
            
            for backend in self.backends:
                try:
                    async with aiohttp.ClientSession() as session:
                        start = time.time()
                        async with session.get(f"{backend.url}/health", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                            elapsed = time.time() - start
                            
                            if resp.status == 200:
                                backend.healthy = True
                                backend.last_health_check = time.time()
                                print(f"✅ Health check passed: {backend.url} ({elapsed*1000:.0f}ms)")
                            else:
                                backend.healthy = False
                                print(f"⚠️ Health check failed: {backend.url} (status: {resp.status})")
                except Exception as e:
                    backend.healthy = False
                    print(f"❌ Health check error: {backend.url} - {str(e)}")
    
    def get_stats(self) -> dict:
        """Get load balancer statistics"""
        total_requests = sum(b.total_requests for b in self.backends)
        
        return {
            "strategy": self.strategy,
            "total_backends": len(self.backends),
            "healthy_backends": sum(1 for b in self.backends if b.healthy),
            "total_requests": total_requests,
            "backends": [
                {
                    "url": b.url,
                    "healthy": b.healthy,
                    "active_connections": b.active_connections,
                    "total_requests": b.total_requests,
                    "failed_requests": b.failed_requests,
                    "avg_response_time_ms": round(b.avg_response_time * 1000, 2),
                    "weight": b.weight,
                    "load_score": round(b.load_score, 2)
                }
                for b in self.backends
            ]
        }


# ============================================================================
# REQUEST QUEUE AND RATE LIMITING
# ============================================================================

class RequestQueue:
    """Priority queue for handling requests"""
    
    def __init__(self, max_size=1000):
        self.queue = asyncio.PriorityQueue(maxsize=max_size)
        self.processing = False
    
    async def add(self, priority: int, request_data: dict):
        """Add request to queue with priority (lower number = higher priority)"""
        await self.queue.put((priority, time.time(), request_data))
    
    async def process(self, handler):
        """Process queued requests"""
        self.processing = True
        while self.processing:
            try:
                priority, timestamp, request_data = await asyncio.wait_for(
                    self.queue.get(), timeout=1.0
                )
                await handler(request_data)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error processing queue: {e}")
    
    def stop(self):
        self.processing = False
    
    def size(self):
        return self.queue.qsize()


# ============================================================================
# CACHING LAYER
# ============================================================================

class CacheLayer:
    """Simple in-memory cache with TTL"""
    
    def __init__(self, default_ttl=60):
        self.cache = {}
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str):
        """Get cached value"""
        if key in self.cache:
            value, expiry = self.cache[key]
            if time.time() < expiry:
                self.hits += 1
                return value
            else:
                del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, key: str, value, ttl=None):
        """Set cached value"""
        ttl = ttl or self.default_ttl
        expiry = time.time() + ttl
        self.cache[key] = (value, expiry)
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
    
    def stats(self):
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(hit_rate, 2)
        }


# ============================================================================
# MAIN LOAD BALANCER APPLICATION
# ============================================================================

class LoadBalancerApp:
    def __init__(self):
        self.lb = LoadBalancer()
        self.cache = CacheLayer(default_ttl=30)
        self.request_queue = RequestQueue()
        self.rate_limiter = defaultdict(lambda: deque(maxlen=100))
        self.rate_limit = 50  # requests per minute
        
        # Add backend servers (simulating multiple instances)
        self.lb.add_backend("localhost", 5001, weight=2)
        self.lb.add_backend("localhost", 5002, weight=1)
        self.lb.add_backend("localhost", 5003, weight=1)
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client is within rate limit"""
        now = time.time()
        requests = self.rate_limiter[client_ip]
        
        # Remove old requests (older than 1 minute)
        while requests and requests[0] < now - 60:
            requests.popleft()
        
        if len(requests) >= self.rate_limit:
            return False
        
        requests.append(now)
        return True
    
    async def proxy_request(self, request: web.Request) -> web.Response:
        """Main proxy handler with all backend tricks"""
        client_ip = request.remote
        
        # 1. Rate limiting
        if not self.check_rate_limit(client_ip):
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429,
                headers={"Retry-After": "60"}
            )
        
        # 2. Check cache
        cache_key = f"{request.method}:{request.path}:{request.query_string}"
        cached_response = self.cache.get(cache_key)
        if cached_response:
            return web.json_response(
                {"data": cached_response, "cached": True},
                headers={"X-Cache": "HIT"}
            )
        
        # 3. Select backend
        session_id = request.cookies.get('session_id')
        try:
            backend = self.lb.select_backend(client_ip, session_id)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=503)
        
        # 4. Forward request to backend
        backend.active_connections += 1
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Forward request
                url = f"{backend.url}{request.path}"
                if request.query_string:
                    url += f"?{request.query_string}"
                
                async with session.request(
                    method=request.method,
                    url=url,
                    headers=request.headers,
                    data=await request.read(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    response_data = await resp.text()
                    elapsed = time.time() - start_time
                    
                    # Update backend stats
                    backend.total_requests += 1
                    backend.avg_response_time = (
                        (backend.avg_response_time * (backend.total_requests - 1) + elapsed) 
                        / backend.total_requests
                    )
                    
                    # Cache successful GET requests
                    if request.method == "GET" and resp.status == 200:
                        try:
                            json_data = json.loads(response_data)
                            self.cache.set(cache_key, json_data, ttl=30)
                        except:
                            pass
                    
                    return web.Response(
                        text=response_data,
                        status=resp.status,
                        headers={
                            "X-Backend": backend.url,
                            "X-Response-Time": f"{elapsed*1000:.2f}ms",
                            "X-Cache": "MISS"
                        }
                    )
        
        except Exception as e:
            backend.failed_requests += 1
            print(f"❌ Backend error: {backend.url} - {str(e)}")
            
            # Try another backend (retry logic)
            return web.json_response(
                {"error": "Backend unavailable", "details": str(e)},
                status=503
            )
        
        finally:
            backend.active_connections -= 1
    
    async def stats_handler(self, request: web.Request) -> web.Response:
        """Get load balancer statistics"""
        lb_stats = self.lb.get_stats()
        cache_stats = self.cache.stats()
        
        return web.json_response({
            "load_balancer": lb_stats,
            "cache": cache_stats,
            "queue_size": self.request_queue.size(),
            "timestamp": datetime.now().isoformat()
        })
    
    async def change_strategy(self, request: web.Request) -> web.Response:
        """Change load balancing strategy"""
        data = await request.json()
        strategy = data.get("strategy", "least_connections")
        
        valid_strategies = ["round_robin", "least_connections", "weighted", 
                          "ip_hash", "least_response_time", "adaptive"]
        
        if strategy in valid_strategies:
            self.lb.strategy = strategy
            return web.json_response({
                "status": "ok",
                "strategy": strategy
            })
        else:
            return web.json_response({
                "error": "Invalid strategy",
                "valid_strategies": valid_strategies
            }, status=400)
    
    async def dashboard(self, request: web.Request) -> web.Response:
        """Dashboard HTML"""
        html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Load Balancer Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { 
            color: white; 
            text-align: center; 
            margin-bottom: 30px;
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
        }
        .metric-value { 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #2a5298; 
            margin: 10px 0; 
        }
        .metric-label { 
            color: #666; 
            font-size: 0.9em; 
            text-transform: uppercase; 
        }
        .backends-container {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .backend-row {
            display: grid;
            grid-template-columns: 200px 100px 100px 150px 150px 100px;
            gap: 15px;
            padding: 15px;
            border-bottom: 1px solid #eee;
            align-items: center;
        }
        .backend-row:hover { background: #f8f9fa; }
        .backend-header {
            font-weight: bold;
            background: #f0f0f0;
            border-radius: 6px;
        }
        .status-healthy { 
            color: #28a745; 
            font-weight: bold; 
        }
        .status-unhealthy { 
            color: #dc3545; 
            font-weight: bold; 
        }
        .strategy-selector {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        select, button {
            padding: 10px 20px;
            font-size: 1em;
            border-radius: 6px;
            border: 2px solid #2a5298;
            margin-right: 10px;
        }
        button {
            background: #2a5298;
            color: white;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover { background: #1e3c72; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚖️ Load Balancer Dashboard</h1>
        
        <div class="strategy-selector">
            <label>Load Balancing Strategy: </label>
            <select id="strategy">
                <option value="round_robin">Round Robin</option>
                <option value="least_connections" selected>Least Connections</option>
                <option value="weighted">Weighted Round Robin</option>
                <option value="ip_hash">IP Hash</option>
                <option value="least_response_time">Least Response Time</option>
                <option value="adaptive">Adaptive</option>
            </select>
            <button onclick="changeStrategy()">Apply</button>
            <button onclick="loadStats()">Refresh</button>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Total Backends</div>
                <div class="metric-value" id="total-backends">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Healthy Backends</div>
                <div class="metric-value" id="healthy-backends" style="color: #28a745;">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value" id="total-requests">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Cache Hit Rate</div>
                <div class="metric-value" id="cache-hit-rate">0%</div>
            </div>
        </div>

        <div class="backends-container">
            <h3 style="margin-bottom: 15px;">Backend Servers</h3>
            <div class="backend-row backend-header">
                <div>URL</div>
                <div>Status</div>
                <div>Weight</div>
                <div>Active Conns</div>
                <div>Avg Response</div>
                <div>Load Score</div>
            </div>
            <div id="backends-list"></div>
        </div>
    </div>

    <script>
        async function loadStats() {
            const response = await fetch('/stats');
            const data = await response.json();
            
            document.getElementById('total-backends').textContent = data.load_balancer.total_backends;
            document.getElementById('healthy-backends').textContent = data.load_balancer.healthy_backends;
            document.getElementById('total-requests').textContent = data.load_balancer.total_requests;
            document.getElementById('cache-hit-rate').textContent = data.cache.hit_rate + '%';
            document.getElementById('strategy').value = data.load_balancer.strategy;
            
            const backendsList = document.getElementById('backends-list');
            backendsList.innerHTML = '';
            
            data.load_balancer.backends.forEach(backend => {
                const row = document.createElement('div');
                row.className = 'backend-row';
                const statusClass = backend.healthy ? 'status-healthy' : 'status-unhealthy';
                const statusText = backend.healthy ? '✅ Healthy' : '❌ Down';
                
                row.innerHTML = `
                    <div>${backend.url}</div>
                    <div class="${statusClass}">${statusText}</div>
                    <div>${backend.weight}</div>
                    <div>${backend.active_connections}</div>
                    <div>${backend.avg_response_time_ms}ms</div>
                    <div>${backend.load_score}</div>
                `;
                backendsList.appendChild(row);
            });
        }
        
        async function changeStrategy() {
            const strategy = document.getElementById('strategy').value;
            await fetch('/change_strategy', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({strategy})
            });
            loadStats();
        }
        
        // Load stats on page load and refresh every 3 seconds
        loadStats();
        setInterval(loadStats, 3000);
    </script>
</body>
</html>
        '''
        return web.Response(text=html, content_type='text/html')


async def init_app():
    """Initialize the application"""
    app_instance = LoadBalancerApp()
    
    app = web.Application()
    app.router.add_get('/dashboard', app_instance.dashboard)
    app.router.add_get('/stats', app_instance.stats_handler)
    app.router.add_post('/change_strategy', app_instance.change_strategy)
    app.router.add_route('*', '/{path:.*}', app_instance.proxy_request)
    
    # Start health checks
    asyncio.create_task(app_instance.lb.health_check())
    
    return app


def main():
    """Main entry point"""
    print("="*60)
    print("🚀 Starting Advanced Load Balancer")
    print("="*60)
    print("\n📊 Dashboard: http://localhost:8080/dashboard")
    print("📈 Stats API: http://localhost:8080/stats")
    print("\n⚠️  Note: Make sure backend servers are running on ports 5001-5003")
    print("="*60 + "\n")
    
    web.run_app(init_app(), host='0.0.0.0', port=8080)


if __name__ == '__main__':
    main()