import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor
import threading

BASE_URL = "http://localhost:5000"

def test_basic_request(api_key):
    response = requests.get(
        "http://127.0.0.1:5000/data",
        params={"api_key": api_key},
        timeout=5
    )

    try:
        body = response.json()
    except ValueError:
        body = response.text  # fallback for HTML / empty

    print(f"[{api_key}] Status: {response.status_code} - {body}")
    return response.status_code




def test_rate_limiting(api_key, num_requests=10):
    """Test rate limiting by making multiple requests"""
    print(f"\n{'='*60}")
    print(f"Testing Rate Limiting for {api_key}")
    print(f"{'='*60}")
    
    for i in range(num_requests):
        status = test_basic_request(api_key)
        time.sleep(0.5)  # Small delay between requests
    
    # Check usage
    usage_response = requests.get(f"{BASE_URL}/usage", params={"api_key": api_key})
    print(f"\nUsage Info: {json.dumps(usage_response.json(), indent=2)}")

def test_tier_upgrade():
    """Test tier upgrade functionality"""
    print(f"\n{'='*60}")
    print("Testing Tier Upgrade")
    print(f"{'='*60}")
    
    api_key = "premium_user_123"
    
    # Upgrade to premium
    upgrade_response = requests.post(
        f"{BASE_URL}/admin/upgrade_tier",
        json={"api_key": api_key, "tier": "premium"}
    )
    print(f"Upgrade Response: {upgrade_response.json()}")
    
    # Test with premium limits
    print(f"\nTesting with premium tier (100 requests/60s)...")
    for i in range(15):
        test_basic_request(api_key)
        time.sleep(0.3)
    
    usage = requests.get(f"{BASE_URL}/usage", params={"api_key": api_key})
    print(f"\nPremium Usage: {json.dumps(usage.json(), indent=2)}")

def test_ip_rate_limiting():
    """Test IP-based rate limiting"""
    print(f"\n{'='*60}")
    print("Testing IP Rate Limiting")
    print(f"{'='*60}")
    
    # Make many requests from same IP (should trigger IP limit)
    for i in range(110):
        response = requests.get(f"{BASE_URL}/data", params={"api_key": f"user_{i}"})
        if response.status_code == 429:
            print(f"IP Rate Limited at request {i+1}")
            print(f"Response: {response.json()}")
            break
        if i % 20 == 0:
            print(f"Request {i+1}: OK")

def test_concurrent_requests():
    """Test concurrent requests to simulate load"""
    print(f"\n{'='*60}")
    print("Testing Concurrent Requests")
    print(f"{'='*60}")
    
    def make_request(index):
        api_key = f"concurrent_user_{index % 5}"  # 5 different users
        response = requests.get(f"{BASE_URL}/data", params={"api_key": api_key})
        return response.status_code
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request, i) for i in range(50)]
        results = [f.result() for f in futures]
    
    print(f"\nResults: {results.count(200)} successful, {results.count(429)} rate limited")

def test_admin_operations():
    """Test admin operations"""
    print(f"\n{'='*60}")
    print("Testing Admin Operations")
    print(f"{'='*60}")
    
    api_key = "bad_user_456"
    
    # Make some requests
    print(f"\nMaking requests with {api_key}...")
    for i in range(3):
        test_basic_request(api_key)
    
    # Block the key
    print(f"\nBlocking {api_key}...")
    block_response = requests.post(
        f"{BASE_URL}/admin/block_key",
        json={"api_key": api_key}
    )
    print(f"Block Response: {block_response.json()}")
    
    # Try to use blocked key
    print(f"\nTrying to use blocked key...")
    blocked_response = requests.get(f"{BASE_URL}/data", params={"api_key": api_key})
    print(f"Response: {blocked_response.status_code} - {blocked_response.json()}")
    
    # Unblock the key
    print(f"\nUnblocking {api_key}...")
    unblock_response = requests.post(
        f"{BASE_URL}/admin/unblock_key",
        json={"api_key": api_key}
    )
    print(f"Unblock Response: {unblock_response.json()}")
    
    # Try again
    print(f"\nTrying to use unblocked key...")
    unblocked_response = requests.get(f"{BASE_URL}/data", params={"api_key": api_key})
    print(f"Response: {unblocked_response.status_code} - {unblocked_response.json()}")

def test_real_time_monitoring():
    """Test real-time monitoring and metrics"""
    print(f"\n{'='*60}")
    print("Testing Real-time Monitoring")
    print(f"{'='*60}")
    
    print("\nGenerating traffic for monitoring...")
    
    # Generate diverse traffic
    def generate_traffic():
        for i in range(20):
            api_key = f"monitor_user_{i % 3}"
            requests.get(f"{BASE_URL}/data", params={"api_key": api_key})
            time.sleep(0.2)
    
    # Run in background thread
    thread = threading.Thread(target=generate_traffic)
    thread.start()
    
    # Check metrics
    time.sleep(2)
    metrics = requests.get(f"{BASE_URL}/api/metrics")
    print(f"\nCurrent Metrics:")
    print(json.dumps(metrics.json(), indent=2))
    
    thread.join()
    
    print(f"\n✅ Open http://localhost:5000/dashboard in your browser to see real-time updates!")

def view_all_users():
    """View all users in the system"""
    print(f"\n{'='*60}")
    print("All Users in System")
    print(f"{'='*60}")
    
    response = requests.get(f"{BASE_URL}/admin/users")
    users = response.json()['users']
    
    print(f"\nTotal Users: {len(users)}\n")
    for user in users:
        print(f"API Key: {user['api_key']}")
        print(f"  Tier: {user['tier']}")
        print(f"  Total Requests: {user['total_requests']}")
        print(f"  Current Window: {user['current_count']}")
        print(f"  Blocked: {user['blocked']}")
        print(f"  Created: {user['created_at']}\n")

def view_logs():
    """View recent logs"""
    print(f"\n{'='*60}")
    print("Recent Logs")
    print(f"{'='*60}")
    
    response = requests.get(f"{BASE_URL}/logs?limit=20")
    logs = response.json()['logs']
    
    print(f"\nShowing last {len(logs)} requests:\n")
    for log in logs:
        print(f"[{log['timestamp']}] {log['api_key']} -> {log['endpoint']} | Status: {log['status_code']} | {log['response_time_ms']}ms")

def main():
    """Run all tests"""
    print("="*60)
    print("🚀 Enhanced Rate Limiter Test Suite")
    print("="*60)
    
    try:
        # Basic tests
        test_rate_limiting("free_user_123", num_requests=8)
        
        # Tier upgrade test
        test_tier_upgrade()
        
        # IP limiting test (uncomment if you want to test this)
        # test_ip_rate_limiting()
        
        # Concurrent requests
        test_concurrent_requests()
        
        # Admin operations
        test_admin_operations()
        
        # Real-time monitoring
        test_real_time_monitoring()
        
        # View system state
        view_all_users()
        view_logs()
        
        print("\n" + "="*60)
        print("✅ All Tests Complete!")
        print("="*60)
        print("\n🌐 Visit http://localhost:5000/dashboard for the real-time dashboard")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to the server.")
        print("Make sure the Flask app is running on http://localhost:5000")
        print("\nStart it with: python app.py")

if __name__ == "__main__":
    main()