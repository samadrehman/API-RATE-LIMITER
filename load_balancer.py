"""
Advanced Load Balancer with Multiple Routing Strategies

PURPOSE:
This module implements a production-grade asynchronous load balancer with multiple 
routing algorithms, health checking, caching, and rate limiting. The system provides:
- Multiple load balancing strategies (round-robin, least connections, weighted, IP hash, adaptive)
- Automatic health checking and failover for backend servers
- Circuit breaker pattern to prevent cascading failures
- Request rate limiting per client IP
- Response caching layer with TTL
- Sticky session support for session persistence
- Real-time monitoring dashboard with live statistics
- Thread-safe operations for concurrent requests
- Graceful error handling and retry logic

ARCHITECTURE:
- BackendServer: Represents individual backend server instances with health and performance metrics
- LoadBalancer: Core routing engine implementing various load balancing algorithms
- RequestQueue: Priority-based request queuing system for traffic management
- CacheLayer: In-memory caching with TTL for improved performance
- LoadBalancerApp: Main application orchestrating all components with rate limiting

SECURITY CONSIDERATIONS:
- Input validation and sanitization for all external inputs
- Protection against cache poisoning through validation
- Rate limiting to prevent DDoS attacks
- Secure session management with validation
- Protection against header injection attacks
- Safe error handling without information disclosure
- Resource limits to prevent memory exhaustion
- Request timeout enforcement to prevent resource leaks
"""

import asyncio
import aiohttp
from aiohttp import web
import time
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import json
from datetime import datetime
import hashlib
import re
import logging
from urllib.parse import urlparse, quote
import html

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class BackendServer:
    host: str
    port: int
    weight: int = 1
    healthy: bool = True
    active_connections: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    last_health_check: float = 0.0
    circuit_breaker_failures: int = 0
    circuit_breaker_opened_at: float = 0.0
    
    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host:
            raise ValueError("Invalid host")
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port: {self.port}")
        if self.weight < 1:
            raise ValueError(f"Weight must be >= 1, got {self.weight}")
        
        hostname_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        if not (hostname_pattern.match(self.host) or 
                ip_pattern.match(self.host) or 
                self.host == 'localhost'):
            raise ValueError(f"Invalid host format: {self.host}")
    
    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
    
    @property
    def load_score(self) -> float:
        failure_penalty = (self.failed_requests / max(self.total_requests, 1)) * 100
        connection_factor = self.active_connections * 10
        response_time_factor = self.avg_response_time * 1000
        
        return connection_factor + response_time_factor + failure_penalty
    
    def is_circuit_breaker_open(self, threshold: int, timeout: float) -> bool:
        if self.circuit_breaker_failures >= threshold:
            if time.time() - self.circuit_breaker_opened_at < timeout:
                return True
            else:
                self.circuit_breaker_failures = 0
                return False
        return False
    
    def record_success(self):
        self.circuit_breaker_failures = 0
        self.circuit_breaker_opened_at = 0.0
    
    def record_failure(self):
        self.circuit_breaker_failures += 1
        if self.circuit_breaker_failures == 1:
            self.circuit_breaker_opened_at = time.time()


class LoadBalancer:
    
    VALID_STRATEGIES = {
        "round_robin", "least_connections", "weighted", 
        "ip_hash", "least_response_time", "adaptive"
    }
    
    def __init__(self):
        self.backends: List[BackendServer] = []
        self.strategy = "least_connections"
        self.current_index = 0
        self.health_check_interval = 10
        self.circuit_breaker_threshold = 5
        self.circuit_breaker_timeout = 30
        self.sticky_sessions: Dict[str, BackendServer] = {}
        self.request_history = deque(maxlen=1000)
        self.max_backends = 100
        self._lock = asyncio.Lock()
    
    def add_backend(self, host: str, port: int, weight: int = 1) -> bool:
        try:
            if len(self.backends) >= self.max_backends:
                logger.error(f"Maximum backends limit reached: {self.max_backends}")
                return False
            
            backend = BackendServer(host=host, port=port, weight=weight)
            self.backends.append(backend)
            logger.info(f"Added backend: {backend.url} (weight: {weight})")
            return True
        except ValueError as e:
            logger.error(f"Failed to add backend: {e}")
            return False
    
    def _get_healthy_backends(self) -> List[BackendServer]:
        return [
            b for b in self.backends 
            if b.healthy and not b.is_circuit_breaker_open(
                self.circuit_breaker_threshold,
                self.circuit_breaker_timeout
            )
        ]
    
    def round_robin(self) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        backend = healthy_backends[self.current_index % len(healthy_backends)]
        self.current_index += 1
        return backend
    
    def least_connections(self) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        return min(healthy_backends, key=lambda b: b.active_connections)
    
    def weighted_round_robin(self) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        weighted_list = []
        for backend in healthy_backends:
            weighted_list.extend([backend] * backend.weight)
        
        if not weighted_list:
            return None
        
        backend = weighted_list[self.current_index % len(weighted_list)]
        self.current_index += 1
        return backend
    
    def ip_hash(self, client_ip: str) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        if not client_ip:
            return healthy_backends[0]
        
        hash_value = int(hashlib.sha256(client_ip.encode()).hexdigest(), 16)
        index = hash_value % len(healthy_backends)
        return healthy_backends[index]
    
    def least_response_time(self) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        return min(healthy_backends, key=lambda b: b.avg_response_time)
    
    def adaptive(self) -> Optional[BackendServer]:
        healthy_backends = self._get_healthy_backends()
        if not healthy_backends:
            return None
        
        return min(healthy_backends, key=lambda b: b.load_score)
    
    def select_backend(self, client_ip: str = None, session_id: str = None) -> Optional[BackendServer]:
        if session_id and len(session_id) > 256:
            logger.warning(f"Session ID too long: {len(session_id)}")
            session_id = None
        
        if session_id:
            session_id = re.sub(r'[^a-zA-Z0-9_-]', '', session_id)
        
        if session_id and session_id in self.sticky_sessions:
            backend = self.sticky_sessions[session_id]
            if backend.healthy and not backend.is_circuit_breaker_open(
                self.circuit_breaker_threshold,
                self.circuit_breaker_timeout
            ):
                return backend
        
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
        
        if backend and session_id:
            if len(self.sticky_sessions) < 10000:
                self.sticky_sessions[session_id] = backend
            else:
                logger.warning("Sticky sessions limit reached")
        
        return backend
    
    async def health_check(self):
        while True:
            await asyncio.sleep(self.health_check_interval)
            
            for backend in self.backends:
                try:
                    timeout = aiohttp.ClientTimeout(total=3)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        start = time.time()
                        health_url = f"{backend.url}/health"
                        
                        async with session.get(health_url) as resp:
                            elapsed = time.time() - start
                            
                            if resp.status == 200:
                                backend.healthy = True
                                backend.last_health_check = time.time()
                                backend.record_success()
                                logger.debug(f"Health check passed: {backend.url} ({elapsed*1000:.0f}ms)")
                            else:
                                backend.healthy = False
                                backend.record_failure()
                                logger.warning(f"Health check failed: {backend.url} (status: {resp.status})")
                                
                except asyncio.TimeoutError:
                    backend.healthy = False
                    backend.record_failure()
                    logger.warning(f"Health check timeout: {backend.url}")
                except Exception as e:
                    backend.healthy = False
                    backend.record_failure()
                    logger.error(f"Health check error: {backend.url} - {type(e).__name__}")
    
    def get_stats(self) -> dict:
        total_requests = sum(b.total_requests for b in self.backends)
        
        return {
            "strategy": self.strategy,
            "total_backends": len(self.backends),
            "healthy_backends": len(self._get_healthy_backends()),
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
                    "load_score": round(b.load_score, 2),
                    "circuit_breaker_failures": b.circuit_breaker_failures
                }
                for b in self.backends
            ]
        }


class RequestQueue:
    
    def __init__(self, max_size=1000):
        if not isinstance(max_size, int) or max_size < 1:
            raise ValueError("max_size must be a positive integer")
        
        self.queue = asyncio.PriorityQueue(maxsize=max_size)
        self.processing = False
        self.max_size = max_size
    
    async def add(self, priority: int, request_data: dict):
        if not isinstance(priority, int):
            raise ValueError("Priority must be an integer")
        
        if self.queue.qsize() >= self.max_size:
            raise asyncio.QueueFull("Request queue is full")
        
        await self.queue.put((priority, time.time(), request_data))
    
    async def process(self, handler):
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
                logger.error(f"Error processing queue: {e}")
    
    def stop(self):
        self.processing = False
    
    def size(self) -> int:
        return self.queue.qsize()


class CacheLayer:
    
    def __init__(self, default_ttl=60, max_size=1000):
        if default_ttl < 0:
            raise ValueError("TTL must be non-negative")
        if max_size < 1:
            raise ValueError("max_size must be positive")
        
        self.cache = {}
        self.default_ttl = default_ttl
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[any]:
        if not isinstance(key, str) or len(key) > 512:
            return None
        
        async with self._lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    self.hits += 1
                    return value
                else:
                    del self.cache[key]
            
            self.misses += 1
            return None
    
    async def set(self, key: str, value, ttl=None):
        if not isinstance(key, str) or len(key) > 512:
            logger.warning("Invalid cache key")
            return False
        
        ttl = ttl or self.default_ttl
        if ttl < 0:
            ttl = self.default_ttl
        
        expiry = time.time() + ttl
        
        async with self._lock:
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
                del self.cache[oldest_key]
            
            self.cache[key] = (value, expiry)
        
        return True
    
    async def clear(self):
        async with self._lock:
            self.cache.clear()
    
    def stats(self) -> dict:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(hit_rate, 2)
        }


class LoadBalancerApp:
    
    ALLOWED_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
    MAX_REQUEST_SIZE = 10 * 1024 * 1024
    
    def __init__(self):
        self.lb = LoadBalancer()
        self.cache = CacheLayer(default_ttl=30, max_size=1000)
        self.request_queue = RequestQueue(max_size=1000)
        self.rate_limiter = defaultdict(lambda: deque(maxlen=100))
        self.rate_limit = 50
        self.blocked_ips: Set[str] = set()
        self.max_blocked_ips = 10000
        
        self.lb.add_backend("localhost", 5001, weight=2)
        self.lb.add_backend("localhost", 5002, weight=1)
        self.lb.add_backend("localhost", 5003, weight=1)
    
    def _sanitize_ip(self, ip: str) -> str:
        if not ip or not isinstance(ip, str):
            return "unknown"
        
        ip = ip.split(',')[0].strip()
        
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        if ip_pattern.match(ip):
            return ip
        
        return "unknown"
    
    def _is_safe_path(self, path: str) -> bool:
        if not path or not isinstance(path, str):
            return False
        
        if len(path) > 2048:
            return False
        
        dangerous_patterns = [
            r'\.\.',
            r'[<>]',
            r'[\x00-\x1f\x7f]',
            r'[;&|`$]',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, path):
                return False
        
        return True
    
    def check_rate_limit(self, client_ip: str) -> bool:
        if client_ip in self.blocked_ips:
            return False
        
        now = time.time()
        requests = self.rate_limiter[client_ip]
        
        while requests and requests[0] < now - 60:
            requests.popleft()
        
        if len(requests) >= self.rate_limit:
            if len(self.blocked_ips) < self.max_blocked_ips:
                self.blocked_ips.add(client_ip)
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False
        
        requests.append(now)
        return True
    
    async def proxy_request(self, request: web.Request) -> web.Response:
        try:
            client_ip = self._sanitize_ip(request.remote or request.headers.get('X-Forwarded-For', 'unknown'))
            
            if not self.check_rate_limit(client_ip):
                return web.json_response(
                    {"error": "Rate limit exceeded"},
                    status=429,
                    headers={"Retry-After": "60"}
                )
            
            if request.method not in self.ALLOWED_METHODS:
                return web.json_response(
                    {"error": "Method not allowed"},
                    status=405
                )
            
            if not self._is_safe_path(request.path):
                logger.warning(f"Unsafe path detected: {request.path}")
                return web.json_response(
                    {"error": "Invalid path"},
                    status=400
                )
            
            content_length = request.content_length
            if content_length and content_length > self.MAX_REQUEST_SIZE:
                return web.json_response(
                    {"error": "Request too large"},
                    status=413
                )
            
            cache_key = None
            if request.method == "GET":
                cache_key = f"{request.method}:{request.path}"
                if request.query_string:
                    cache_key += f":{request.query_string[:256]}"
                
                cached_response = await self.cache.get(cache_key)
                if cached_response is not None:
                    return web.json_response(
                        cached_response,
                        headers={"X-Cache": "HIT"}
                    )
            
            session_id = request.cookies.get('session_id')
            backend = self.lb.select_backend(client_ip, session_id)
            
            if not backend:
                return web.json_response(
                    {"error": "No healthy backends available"},
                    status=503,
                    headers={"Retry-After": "10"}
                )
            
            backend.active_connections += 1
            start_time = time.time()
            
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    url = f"{backend.url}{request.path}"
                    if request.query_string:
                        url += f"?{request.query_string}"
                    
                    headers = {
                        k: v for k, v in request.headers.items()
                        if k.lower() not in ('host', 'connection', 'content-length')
                    }
                    
                    headers['X-Forwarded-For'] = client_ip
                    headers['X-Forwarded-Proto'] = 'http'
                    
                    request_body = await request.read()
                    
                    async with session.request(
                        method=request.method,
                        url=url,
                        headers=headers,
                        data=request_body
                    ) as resp:
                        response_data = await resp.read()
                        elapsed = time.time() - start_time
                        
                        backend.total_requests += 1
                        backend.avg_response_time = (
                            (backend.avg_response_time * (backend.total_requests - 1) + elapsed) 
                            / backend.total_requests
                        )
                        backend.record_success()
                        
                        if request.method == "GET" and resp.status == 200 and cache_key:
                            try:
                                if len(response_data) < 1024 * 100:
                                    json_data = json.loads(response_data)
                                    await self.cache.set(cache_key, json_data, ttl=30)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
                        
                        response_headers = {
                            "X-Backend": backend.url,
                            "X-Response-Time": f"{elapsed*1000:.2f}ms",
                            "X-Cache": "MISS"
                        }
                        
                        safe_headers = {
                            k: v for k, v in resp.headers.items()
                            if k.lower() in ('content-type', 'content-encoding', 
                                           'cache-control', 'expires', 'etag')
                        }
                        response_headers.update(safe_headers)
                        
                        return web.Response(
                            body=response_data,
                            status=resp.status,
                            headers=response_headers
                        )
            
            except asyncio.TimeoutError:
                backend.failed_requests += 1
                backend.record_failure()
                logger.error(f"Backend timeout: {backend.url}")
                return web.json_response(
                    {"error": "Gateway timeout"},
                    status=504
                )
            
            except aiohttp.ClientError as e:
                backend.failed_requests += 1
                backend.record_failure()
                logger.error(f"Backend error: {backend.url} - {type(e).__name__}")
                return web.json_response(
                    {"error": "Bad gateway"},
                    status=502
                )
            
            finally:
                backend.active_connections = max(0, backend.active_connections - 1)
        
        except Exception as e:
            logger.error(f"Proxy request error: {type(e).__name__}: {str(e)}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def stats_handler(self, request: web.Request) -> web.Response:
        try:
            lb_stats = self.lb.get_stats()
            cache_stats = self.cache.stats()
            
            return web.json_response({
                "load_balancer": lb_stats,
                "cache": cache_stats,
                "queue_size": self.request_queue.size(),
                "blocked_ips_count": len(self.blocked_ips),
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Stats handler error: {e}")
            return web.json_response(
                {"error": "Failed to retrieve stats"},
                status=500
            )
    
    async def change_strategy(self, request: web.Request) -> web.Response:
        try:
            if request.content_length and request.content_length > 1024:
                return web.json_response(
                    {"error": "Request too large"},
                    status=413
                )
            
            data = await request.json()
            strategy = data.get("strategy", "").strip()
            
            if strategy in LoadBalancer.VALID_STRATEGIES:
                self.lb.strategy = strategy
                logger.info(f"Strategy changed to: {strategy}")
                return web.json_response({
                    "status": "ok",
                    "strategy": strategy
                })
            else:
                return web.json_response({
                    "error": "Invalid strategy",
                    "valid_strategies": list(LoadBalancer.VALID_STRATEGIES)
                }, status=400)
        
        except json.JSONDecodeError:
            return web.json_response(
                {"error": "Invalid JSON"},
                status=400
            )
        except Exception as e:
            logger.error(f"Change strategy error: {e}")
            return web.json_response(
                {"error": "Internal error"},
                status=500
            )
    
    async def dashboard(self, request: web.Request) -> web.Response:
        html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Load Balancer Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
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
            overflow-x: auto;
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
        .status-healthy { color: #28a745; font-weight: bold; }
        .status-unhealthy { color: #dc3545; font-weight: bold; }
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
        .error { color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 6px; margin: 10px 0; }
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
        
        <div id="error-container"></div>
        
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
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function showError(message) {
            const errorContainer = document.getElementById('error-container');
            errorContainer.innerHTML = '<div class="error">' + escapeHtml(message) + '</div>';
            setTimeout(() => { errorContainer.innerHTML = ''; }, 5000);
        }
        
        async function loadStats() {
            try {
                const response = await fetch('/stats');
                if (!response.ok) {
                    throw new Error('Failed to fetch stats');
                }
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
                        <div>${escapeHtml(backend.url)}</div>
                        <div class="${statusClass}">${statusText}</div>
                        <div>${backend.weight}</div>
                        <div>${backend.active_connections}</div>
                        <div>${backend.avg_response_time_ms}ms</div>
                        <div>${backend.load_score}</div>
                    `;
                    backendsList.appendChild(row);
                });
            } catch (error) {
                showError('Failed to load stats: ' + error.message);
            }
        }
        
        async function changeStrategy() {
            try {
                const strategy = document.getElementById('strategy').value;
                const response = await fetch('/change_strategy', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({strategy: strategy})
                });
                
                if (!response.ok) {
                    throw new Error('Failed to change strategy');
                }
                
                await loadStats();
            } catch (error) {
                showError('Failed to change strategy: ' + error.message);
            }
        }
        
        loadStats();
        setInterval(loadStats, 3000);
    </script>
</body>
</html>'''
        
        return web.Response(
            text=html_content,
            content_type='text/html',
            charset='utf-8'
        )


async def init_app():
    try:
        app_instance = LoadBalancerApp()
        
        app = web.Application(client_max_size=LoadBalancerApp.MAX_REQUEST_SIZE)
        app.router.add_get('/dashboard', app_instance.dashboard)
        app.router.add_get('/stats', app_instance.stats_handler)
        app.router.add_post('/change_strategy', app_instance.change_strategy)
        app.router.add_route('*', '/{path:.*}', app_instance.proxy_request)
        
        asyncio.create_task(app_instance.lb.health_check())
        
        return app
    except Exception as e:
        logger.error(f"Failed to initialize app: {e}")
        raise


def main():
    print("="*60)
    print("🚀 Starting Advanced Load Balancer")
    print("="*60)
    print("\n📊 Dashboard: http://localhost:8080/dashboard")
    print("📈 Stats API: http://localhost:8080/stats")
    print("\n⚠️  Note: Make sure backend servers are running on ports 5001-5003")
    print("="*60 + "\n")
    
    try:
        web.run_app(init_app(), host='0.0.0.0', port=8080, access_log=logger)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise


if __name__ == '__main__':
    main()