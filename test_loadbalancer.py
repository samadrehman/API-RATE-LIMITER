import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import statistics

LOAD_BALANCER_URL = "http://localhost:8080"

def test_basic_request():
    """Test basic proxied request"""
    print("\n" + "="*60)
    print("TEST 1: Basic Request Proxying")
    print("="*60)
    
    response = requests.get(f"{LOAD_BALANCER_URL}/data?api_key=test_user_123")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print(f"Backend: {response.headers.get('X-Backend')}")
    print(f"Response Time: {response.headers.get('X-Response-Time')}")
    print(f"Cache: {response.headers.get('X-Cache')}")


def test_load_distribution():
    """Test load distribution across backends"""
    print("\n" + "="*60)
    print("TEST 2: Load Distribution")
    print("="*60)
    
    backend_counts = defaultdict(int)
    num_requests = 30
    
    print(f"Sending {num_requests} requests...")
    
    for i in range(num_requests):
        try:
            response = requests.get(f"{LOAD_BALANCER_URL}/data?api_key=user_{i}")
            backend = response.headers.get('X-Backend', 'unknown')
            backend_counts[backend] += 1
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{num_requests}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n📊 Distribution Results:")
    for backend, count in sorted(backend_counts.items()):
        percentage = (count / num_requests) * 100
        bar = "█" * int(percentage / 2)
        print(f"  {backend}: {count} requests ({percentage:.1f}%) {bar}")


def test_different_strategies():
    """Test different load balancing strategies"""
    print("\n" + "="*60)
    print("TEST 3: Load Balancing Strategies")
    print("="*60)
    
    strategies = [
        "round_robin",
        "least_connections",
        "weighted",
        "least_response_time",
        "adaptive"
    ]
    
    for strategy in strategies:
        print(f"\n🔄 Testing strategy: {strategy}")
        
        # Change strategy
        requests.post(
            f"{LOAD_BALANCER_URL}/change_strategy",
            json={"strategy": strategy}
        )
        time.sleep(0.5)
        
        # Make requests
        backend_counts = defaultdict(int)
        for i in range(15):
            response = requests.get(f"{LOAD_BALANCER_URL}/data?api_key=strategy_test_{i}")
            backend = response.headers.get('X-Backend', 'unknown')
            backend_counts[backend] += 1
        
        print(f"  Distribution:")
        for backend, count in sorted(backend_counts.items()):
            print(f"    {backend}: {count} requests")


def test_caching():
    """Test caching functionality"""
    print("\n" + "="*60)
    print("TEST 4: Response Caching")
    print("="*60)
    
    endpoint = f"{LOAD_BALANCER_URL}/data?api_key=cache_test_user"
    
    # First request (should be MISS)
    print("Making first request (expect cache MISS)...")
    resp1 = requests.get(endpoint)
    cache1 = resp1.headers.get('X-Cache')
    time1 = resp1.headers.get('X-Response-Time')
    print(f"  Cache: {cache1}, Response Time: {time1}")
    
    # Second request (should be HIT)
    print("\nMaking second request (expect cache HIT)...")
    time.sleep(0.5)
    resp2 = requests.get(endpoint)
    cache2 = resp2.headers.get('X-Cache')
    time2 = resp2.headers.get('X-Response-Time')
    print(f"  Cache: {cache2}, Response Time: {time2}")
    
    if cache1 == 'MISS' and cache2 == 'HIT':
        print("\n✅ Caching works correctly!")
    else:
        print("\n⚠️  Caching might not be working as expected")


def test_concurrent_load():
    """Test concurrent requests"""
    print("\n" + "="*60)
    print("TEST 5: Concurrent Load Test")
    print("="*60)
    
    num_concurrent = 50
    print(f"Sending {num_concurrent} concurrent requests...")
    
    start_time = time.time()
    response_times = []
    status_codes = defaultdict(int)
    backend_distribution = defaultdict(int)
    
    def make_request(i):
        try:
            resp = requests.get(
                f"{LOAD_BALANCER_URL}/data?api_key=concurrent_user_{i}",
                timeout=10
            )
            
            response_time = float(resp.headers.get('X-Response-Time', '0').replace('ms', ''))
            backend = resp.headers.get('X-Backend', 'unknown')
            
            return {
                'status': resp.status_code,
                'response_time': response_time,
                'backend': backend
            }
        except Exception as e:
            return {
                'status': 0,
                'response_time': 0,
                'backend': 'error',
                'error': str(e)
            }
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(make_request, i) for i in range(num_concurrent)]
        
        for future in as_completed(futures):
            result = future.result()
            status_codes[result['status']] += 1
            if result['response_time'] > 0:
                response_times.append(result['response_time'])
            backend_distribution[result['backend']] += 1
    
    elapsed = time.time() - start_time
    
    print(f"\n⏱️  Total time: {elapsed:.2f}s")
    print(f"📊 Requests/second: {num_concurrent/elapsed:.2f}")
    
    print(f"\n📈 Status Codes:")
    for status, count in sorted(status_codes.items()):
        print(f"  {status}: {count}")
    
    if response_times:
        print(f"\n⚡ Response Times:")
        print(f"  Min: {min(response_times):.2f}ms")
        print(f"  Max: {max(response_times):.2f}ms")
        print(f"  Avg: {statistics.mean(response_times):.2f}ms")
        print(f"  Median: {statistics.median(response_times):.2f}ms")
    
    print(f"\n🎯 Backend Distribution:")
    for backend, count in sorted(backend_distribution.items()):
        print(f"  {backend}: {count}")


def test_rate_limiting():
    """Test rate limiting"""
    print("\n" + "="*60)
    print("TEST 6: Rate Limiting")
    print("="*60)
    
    print("Sending 60 rapid requests from same IP...")
    
    rate_limited = False
    for i in range(60):
        response = requests.get(f"{LOAD_BALANCER_URL}/data?api_key=rate_test_{i}")
        
        if response.status_code == 429:
            print(f"⚠️  Rate limited at request {i+1}")
            print(f"Response: {response.json()}")
            retry_after = response.headers.get('Retry-After')
            print(f"Retry-After: {retry_after}s")
            rate_limited = True
            break
        
        if (i + 1) % 20 == 0:
            print(f"  Progress: {i+1}/60")
    
    if not rate_limited:
        print("✅ All requests succeeded (rate limit not triggered)")


def test_health_checks():
    """Test backend health monitoring"""
    print("\n" + "="*60)
    print("TEST 7: Backend Health Monitoring")
    print("="*60)
    
    # Check individual backend health
    backends = [5001, 5002, 5003]
    
    print("Checking backend health directly:")
    for port in backends:
        try:
            response = requests.get(f"http://localhost:{port}/health", timeout=2)
            health_data = response.json()
            print(f"  ✅ Port {port}: {health_data.get('status')} (uptime: {health_data.get('uptime')}s)")
        except Exception as e:
            print(f"  ❌ Port {port}: {str(e)}")
    
    # Get load balancer stats
    print("\nLoad balancer view of backends:")
    stats = requests.get(f"{LOAD_BALANCER_URL}/stats").json()
    
    for backend in stats['load_balancer']['backends']:
        status = "✅ Healthy" if backend['healthy'] else "❌ Unhealthy"
        print(f"  {backend['url']}: {status}")
        print(f"    - Active connections: {backend['active_connections']}")
        print(f"    - Total requests: {backend['total_requests']}")
        print(f"    - Avg response: {backend['avg_response_time_ms']}ms")
        print(f"    - Load score: {backend['load_score']}")


def test_sticky_sessions():
    """Test sticky sessions (IP hash strategy)"""
    print("\n" + "="*60)
    print("TEST 8: Sticky Sessions (IP Hash)")
    print("="*60)
    
    # Switch to IP hash strategy
    requests.post(
        f"{LOAD_BALANCER_URL}/change_strategy",
        json={"strategy": "ip_hash"}
    )
    
    print("Using IP hash strategy...")
    print("Making 10 requests from same client...")
    
    backends_used = set()
    for i in range(10):
        response = requests.get(f"{LOAD_BALANCER_URL}/data?api_key=sticky_test")
        backend = response.headers.get('X-Backend')
        backends_used.add(backend)
        
        if i == 0:
            print(f"  First request routed to: {backend}")
    
    if len(backends_used) == 1:
        print(f"✅ Sticky session working! All requests went to: {list(backends_used)[0]}")
    else:
        print(f"⚠️  Multiple backends used: {backends_used}")


def view_overall_stats():
    """View overall load balancer statistics"""
    print("\n" + "="*60)
    print("OVERALL STATISTICS")
    print("="*60)
    
    stats = requests.get(f"{LOAD_BALANCER_URL}/stats").json()
    
    lb_stats = stats['load_balancer']
    cache_stats = stats['cache']
    
    print(f"\n📊 Load Balancer:")
    print(f"  Strategy: {lb_stats['strategy']}")
    print(f"  Total backends: {lb_stats['total_backends']}")
    print(f"  Healthy backends: {lb_stats['healthy_backends']}")
    print(f"  Total requests: {lb_stats['total_requests']}")
    
    print(f"\n💾 Cache:")
    print(f"  Size: {cache_stats['size']}")
    print(f"  Hits: {cache_stats['hits']}")
    print(f"  Misses: {cache_stats['misses']}")
    print(f"  Hit rate: {cache_stats['hit_rate']}%")
    
    print(f"\n🖥️  Backends:")
    for backend in lb_stats['backends']:
        print(f"  {backend['url']}:")
        print(f"    Health: {'✅' if backend['healthy'] else '❌'}")
        print(f"    Weight: {backend['weight']}")
        print(f"    Total requests: {backend['total_requests']}")
        print(f"    Failed requests: {backend['failed_requests']}")
        print(f"    Avg response: {backend['avg_response_time_ms']}ms")
        print(f"    Load score: {backend['load_score']}")


def main():
    """Run all tests"""
    print("="*60)
    print("🧪 Load Balancer Test Suite")
    print("="*60)
    
    try:
        # Verify load balancer is running
        requests.get(LOAD_BALANCER_URL, timeout=2)
    except:
        print("\n❌ Error: Load balancer not running!")
        print("Start it with: python load_balancer.py")
        return
    
    tests = [
        ("Basic Request", test_basic_request),
        ("Load Distribution", test_load_distribution),
        ("Strategy Comparison", test_different_strategies),
        ("Caching", test_caching),
        ("Concurrent Load", test_concurrent_load),
        ("Rate Limiting", test_rate_limiting),
        ("Health Checks", test_health_checks),
        ("Sticky Sessions", test_sticky_sessions),
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
            time.sleep(1)  # Pause between tests
        except Exception as e:
            print(f"\n❌ Test '{test_name}' failed: {e}")
    
    # Show final stats
    view_overall_stats()
    
    print("\n" + "="*60)
    print("✅ Test Suite Complete!")
    print("="*60)
    print("\n🌐 View dashboard at: http://localhost:8080/dashboard")


if __name__ == "__main__":
    main()