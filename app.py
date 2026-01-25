import sqlite3
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock

from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit
from flask_cors import CORS

import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# --- Database connection with connection pooling ---
class DatabasePool:
    def __init__(self, db_path='ratelimiter.db', pool_size=5):
        self.db_path = db_path
        self.pool = deque()
        self.pool_size = pool_size
        self.lock = Lock()
        for _ in range(pool_size):
            self.pool.append(sqlite3.connect(db_path, check_same_thread=False))
    
    def get_connection(self):
        with self.lock:
            if self.pool:
                return self.pool.popleft()
            return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def return_connection(self, conn):
        with self.lock:
            if len(self.pool) < self.pool_size:
                self.pool.append(conn)
            else:
                conn.close()

db_pool = DatabasePool()

def get_db():
    return db_pool.get_connection()

def release_db(conn):
    db_pool.return_connection(conn)

# --- Enhanced DB schema with analytics ---
def ensure_db_schema():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key TEXT UNIQUE NOT NULL,
                        request_count INTEGER DEFAULT 0,
                        window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        blocked INTEGER DEFAULT 0,
                        banned_until TEXT DEFAULT NULL,
                        tier TEXT DEFAULT 'free',
                        total_requests INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    
    cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        status_code INTEGER,
                        ip TEXT,
                        user_agent TEXT,
                        response_time_ms INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    
    cursor.execute("""CREATE TABLE IF NOT EXISTS analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_type TEXT NOT NULL,
                        metric_value REAL,
                        metadata TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    
    # Add indexes for better query performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_api_key ON logs(api_key)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics(timestamp)")
    
    conn.commit()
    release_db(conn)

ensure_db_schema()

# --- Tiered Rate Limiting Configuration ---
RATE_LIMITS = {
    'free': {'requests': 5, 'window': 60},
    'basic': {'requests': 20, 'window': 60},
    'premium': {'requests': 100, 'window': 60},
    'enterprise': {'requests': 1000, 'window': 60}
}

RATE_LIMIT_IP = 100
WINDOW_IP = 60
TEMP_BAN_SECONDS = 300
BAN_MULTIPLIER = 2

# --- In-memory structures ---
ip_requests = defaultdict(lambda: deque())
ip_lock = Lock()
banned_ips = {}
banned_ips_lock = Lock()
key_ban_counts = defaultdict(int)
key_ban_lock = Lock()

# Real-time metrics
realtime_metrics = {
    'total_requests': 0,
    'successful_requests': 0,
    'blocked_requests': 0,
    'active_keys': set(),
    'requests_per_second': deque(maxlen=60)
}
metrics_lock = Lock()

# --- Enhanced logging with real-time broadcast ---
def log_request(api_key, endpoint, status_code, ip, user_agent='', response_time_ms=0):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (api_key, endpoint, status_code, ip, user_agent, response_time_ms) VALUES (?, ?, ?, ?, ?, ?)",
        (api_key or "none", endpoint, status_code, ip, user_agent, response_time_ms)
    )
    conn.commit()
    
    # Update total requests for user
    if api_key:
        cursor.execute("UPDATE users SET total_requests = total_requests + 1 WHERE api_key = ?", (api_key,))
        conn.commit()
    
    release_db(conn)
    
    # Update real-time metrics
    with metrics_lock:
        realtime_metrics['total_requests'] += 1
        if status_code == 200:
            realtime_metrics['successful_requests'] += 1
        elif status_code in (403, 429):
            realtime_metrics['blocked_requests'] += 1
        if api_key:
            realtime_metrics['active_keys'].add(api_key)
        realtime_metrics['requests_per_second'].append(time.time())
    
    # Broadcast to connected clients
    socketio.emit('new_request', {
        'api_key': api_key or 'none',
        'endpoint': endpoint,
        'status': status_code,
        'ip': ip,
        'timestamp': datetime.now().isoformat(),
        'response_time': response_time_ms
    })

# --- User management ---
def get_or_create_user(api_key):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, api_key, request_count, window_start_time, blocked, banned_until, tier FROM users WHERE api_key=?", (api_key,))
    user = cursor.fetchone()
    if not user:
        cursor.execute(
            "INSERT INTO users (api_key, request_count, window_start_time, blocked, banned_until, tier) VALUES (?, ?, ?, ?, ?, ?)",
            (api_key, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0, None, 'free')
        )
        conn.commit()
        cursor.execute("SELECT id, api_key, request_count, window_start_time, blocked, banned_until, tier FROM users WHERE api_key=?", (api_key,))
        user = cursor.fetchone()
    release_db(conn)
    return user

def is_key_banned(user_row):
    blocked = user_row[4]
    banned_until = user_row[5]
    if blocked:
        return True, "permanently blocked"
    if banned_until:
        try:
            banned_dt = datetime.strptime(banned_until, "%Y-%m-%d %H:%M:%S")
            if datetime.now() < banned_dt:
                return True, (banned_dt - datetime.now()).total_seconds()
        except Exception:
            return False, None
    return False, None

def ban_key(api_key):
    with key_ban_lock:
        key_ban_counts[api_key] += 1
        multiplier = BAN_MULTIPLIER ** (key_ban_counts[api_key] - 1)
    ban_seconds = int(TEMP_BAN_SECONDS * multiplier)
    banned_until = (datetime.now() + timedelta(seconds=ban_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET banned_until=? WHERE api_key=?", (banned_until, api_key))
    conn.commit()
    release_db(conn)
    return ban_seconds

# --- IP limiting ---
def is_ip_allowed(ip):
    now = time.time()
    with banned_ips_lock:
        ban_until = banned_ips.get(ip)
        if ban_until and now < ban_until:
            return False, int(ban_until - now)

    with ip_lock:
        dq = ip_requests[ip]
        while dq and dq[0] <= now - WINDOW_IP:
            dq.popleft()
        if len(dq) < RATE_LIMIT_IP:
            dq.append(now)
            return True, None
        else:
            ban_seconds = TEMP_BAN_SECONDS
            ban_until = now + ban_seconds
            with banned_ips_lock:
                banned_ips[ip] = ban_until
            return False, ban_seconds

# --- Tiered rate limiting ---
def is_key_allowed(api_key):
    user = get_or_create_user(api_key)
    user_id, key, count, window_start, blocked, banned_until, tier = user

    banned, reason = is_key_banned(user)
    if banned:
        return False, reason

    # Get tier limits
    limits = RATE_LIMITS.get(tier, RATE_LIMITS['free'])
    rate_limit = limits['requests']
    window_size = limits['window']

    try:
        window_start_dt = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()

    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()

    conn = get_db()
    cursor = conn.cursor()

    if elapsed >= window_size:
        cursor.execute("UPDATE users SET request_count=?, window_start_time=? WHERE api_key=?",
                       (1, now.strftime("%Y-%m-%d %H:%M:%S"), api_key))
        conn.commit()
        release_db(conn)
        return True, None
    else:
        if count < rate_limit:
            cursor.execute("UPDATE users SET request_count=? WHERE api_key=?",
                           (count + 1, api_key))
            conn.commit()
            release_db(conn)
            return True, None
        else:
            release_db(conn)
            ban_seconds = ban_key(api_key)
            return False, ban_seconds

def allow_request(api_key):
    ip = request.remote_addr or "unknown"
    ip_ok, ip_info = is_ip_allowed(ip)
    if not ip_ok:
        return False, {"type": "ip", "retry_after": int(ip_info)}

    if not api_key:
        return False, {"type": "auth", "message": "api key required"}

    key_ok, key_info = is_key_allowed(api_key)
    if not key_ok:
        if isinstance(key_info, (int, float)):
            return False, {"type": "key", "retry_after": int(key_info)}
        else:
            return False, {"type": "key", "message": str(key_info)}

    return True, None

# --- Real-time Dashboard HTML ---
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
        h1 { color: white; margin-bottom: 30px; text-align: center; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { 
            background: white; 
            padding: 25px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .metric-card:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0,0,0,0.15); }
        .metric-value { font-size: 2.5em; font-weight: bold; color: #667eea; margin: 10px 0; }
        .metric-label { color: #666; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .chart-container { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .logs-container { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-height: 500px; overflow-y: auto; }
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
        @media (max-width: 768px) {
            .charts { grid-template-columns: 1fr; }
            .log-entry { grid-template-columns: 1fr; gap: 5px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Real-time Rate Limiter Dashboard</h1>
        
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
            <h3 style="margin-bottom: 15px;">📋 Recent Requests</h3>
            <div id="logs"></div>
        </div>
    </div>

    <script>
        const socket = io();
        
        let totalRequests = 0;
        let successfulRequests = 0;
        let blockedRequests = 0;
        let activeKeys = new Set();
        
        // Charts setup
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
        
        // Update metrics
        function updateMetrics() {
            document.getElementById('total-requests').textContent = totalRequests;
            document.getElementById('successful-requests').textContent = successfulRequests;
            document.getElementById('blocked-requests').textContent = blockedRequests;
            document.getElementById('active-keys').textContent = activeKeys.size;
        }
        
        // Handle new requests
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
        
        // Update charts
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
        
        // Add log entry
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
            
            // Keep only last 50 entries
            while (logsDiv.children.length > 50) {
                logsDiv.removeChild(logsDiv.lastChild);
            }
        }
        
        // Load initial metrics
        fetch('/api/metrics')
            .then(r => r.json())
            .then(data => {
                totalRequests = data.total_requests;
                successfulRequests = data.successful_requests;
                blockedRequests = data.blocked_requests;
                data.active_keys.forEach(k => activeKeys.add(k));
                updateMetrics();
            });
    </script>
</body>
</html>
'''

# --- API Endpoints ---
@app.route('/')
def home():
    return jsonify({"message": "🚀 Enhanced API Rate Limiter with Real-time Monitoring", "dashboard": "/dashboard"})

@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/metrics')
def get_metrics():
    with metrics_lock:
        now = time.time()
        recent_requests = [t for t in realtime_metrics['requests_per_second'] if now - t < 1]
        rps = len(recent_requests)
        
        return jsonify({
            'total_requests': realtime_metrics['total_requests'],
            'successful_requests': realtime_metrics['successful_requests'],
            'blocked_requests': realtime_metrics['blocked_requests'],
            'active_keys': list(realtime_metrics['active_keys']),
            'requests_per_second': rps
        })

@app.route('/data')
def get_data():
    start_time = time.time()
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get('User-Agent', '')

    allowed, info = allow_request(api_key)

    if allowed:
        status = 200
        body = {"message": "✅ Here's your protected data!", "timestamp": datetime.now().isoformat()}
    else:
        if info and info.get("type") == "auth":
            status = 400
            body = {"error": info.get("message", "API key required")}
        elif info and info.get("type") == "ip":
            status = 429
            reset = info.get("retry_after", WINDOW_IP)
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
    if status == 429:
        retry = body.get("retry_after_seconds", 60)
        headers["Retry-After"] = str(retry)

    return jsonify(body), status, headers

@app.route('/usage')
def usage():
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"

    if not api_key:
        log_request(None, "/usage", 400, ip)
        return jsonify({"error": "API key required"}), 400

    user = get_or_create_user(api_key)
    _, _, count, window_start, blocked, banned_until, tier = user
    
    limits = RATE_LIMITS.get(tier, RATE_LIMITS['free'])
    
    try:
        window_start_dt = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()
    
    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()
    reset_in = max(0, int(limits['window'] - elapsed))
    requests_left = max(0, limits['requests'] - count)

    log_request(api_key, "/usage", 200, ip)
    return jsonify({
        "tier": tier,
        "requests_left": requests_left,
        "requests_limit": limits['requests'],
        "reset_in_seconds": reset_in,
        "blocked": bool(blocked),
        "banned_until": banned_until
    })

@app.route('/admin/users')
def admin_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT api_key, request_count, total_requests, tier, blocked, banned_until, created_at FROM users")
    users = cursor.fetchall()
    release_db(conn)
    
    return jsonify({
        "users": [
            {
                "api_key": u[0],
                "current_count": u[1],
                "total_requests": u[2],
                "tier": u[3],
                "blocked": bool(u[4]),
                "banned_until": u[5],
                "created_at": u[6]
            }
            for u in users
        ]
    })

@app.route('/admin/upgrade_tier', methods=['POST'])
def upgrade_tier():
    data = request.json or {}
    api_key = data.get("api_key")
    new_tier = data.get("tier", "free")
    
    if not api_key or new_tier not in RATE_LIMITS:
        return jsonify({"error": "Invalid api_key or tier"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET tier=? WHERE api_key=?", (new_tier, api_key))
    conn.commit()
    release_db(conn)
    
    return jsonify({"status": "ok", "message": f"{api_key} upgraded to {new_tier}"})

@app.route('/admin/block_key', methods=['POST'])
def admin_block_key():
    data = request.json or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET blocked=1 WHERE api_key=?", (api_key,))
    conn.commit()
    release_db(conn)
    
    return jsonify({"status": "ok", "message": f"{api_key} blocked"})

@app.route('/admin/unblock_key', methods=['POST'])
def admin_unblock_key():
    data = request.json or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET blocked=0, banned_until=NULL WHERE api_key=?", (api_key,))
    conn.commit()
    release_db(conn)
    
    with key_ban_lock:
        key_ban_counts.pop(api_key, None)
    
    return jsonify({"status": "ok", "message": f"{api_key} unblocked"})

@app.route('/logs')
def logs():
    limit = request.args.get('limit', 100, type=int)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT api_key, endpoint, status_code, ip, timestamp, response_time_ms FROM logs ORDER BY timestamp DESC LIMIT {limit}")
    logs = cursor.fetchall()
    release_db(conn)
    
    return jsonify({
        "logs": [
            {
                "api_key": l[0],
                "endpoint": l[1],
                "status_code": l[2],
                "ip": l[3],
                "timestamp": l[4],
                "response_time_ms": l[5]
            }
            for l in logs
        ]
    })

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'message': 'Connected to rate limiter dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)