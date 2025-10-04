import sqlite3
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock

from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Database connection ---
conn = sqlite3.connect('ratelimiter.db', check_same_thread=False)
cursor = conn.cursor()

# --- Ensure DB schema (adds blocked & banned_until columns if missing) ---
def ensure_db_schema():
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key TEXT UNIQUE NOT NULL,
                        request_count INTEGER DEFAULT 0,
                        window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        status_code INTEGER,
                        ip TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    # add blocked column if missing
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        # column already exists
        pass
    # add banned_until column if missing (stores ISO timestamp or NULL)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN banned_until TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass
    conn.commit()

ensure_db_schema()

# --- Config: limits (tweak these) ---
RATE_LIMIT_KEY = 5        # requests per WINDOW_SIZE per API key
WINDOW_SIZE = 60          # seconds (window duration for API key limiter)

RATE_LIMIT_IP = 50        # max requests per WINDOW_IP seconds per IP
WINDOW_IP = 60            # seconds for IP sliding-window

TEMP_BAN_SECONDS = 300    # initial temporary ban duration (5 minutes)
BAN_MULTIPLIER = 2        # multiply ban duration on repeated ban (simple escalation)

# --- In-memory structures for IP-based sliding window + locks ---
ip_requests = defaultdict(lambda: deque())   # ip -> deque of timestamps (float)
ip_lock = Lock()

# keep track of recent bans in memory for faster checks (mirrors DB for keys)
banned_ips = {}      # ip -> banned_until_timestamp (float)
banned_ips_lock = Lock()

# track how many times a key got banned (for escalation)
key_ban_counts = defaultdict(int)
key_ban_lock = Lock()

# --- Helper: Log each request (with status) ---
def log_request(api_key, endpoint, status_code, ip):
    cursor.execute(
        "INSERT INTO logs (api_key, endpoint, status_code, ip) VALUES (?, ?, ?, ?)",
        (api_key or "none", endpoint, status_code, ip)
    )
    conn.commit()

# --- Helper function to get/create user ---
def get_or_create_user(api_key):
    cursor.execute("SELECT id, api_key, request_count, window_start_time, blocked, banned_until FROM users WHERE api_key=?", (api_key,))
    user = cursor.fetchone()
    if not user:
        cursor.execute(
            "INSERT INTO users (api_key, request_count, window_start_time, blocked, banned_until) VALUES (?, ?, ?, ?, ?)",
            (api_key, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0, None)
        )
        conn.commit()
        cursor.execute("SELECT id, api_key, request_count, window_start_time, blocked, banned_until FROM users WHERE api_key=?", (api_key,))
        user = cursor.fetchone()
    return user

# --- Helpers for bans ---
def is_key_banned(user_row):
    # user_row: (id, api_key, request_count, window_start_time, blocked, banned_until)
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
    # escalate ban based on previous counts
    with key_ban_lock:
        key_ban_counts[api_key] += 1
        multiplier = BAN_MULTIPLIER ** (key_ban_counts[api_key] - 1)
    ban_seconds = int(TEMP_BAN_SECONDS * multiplier)
    banned_until = (datetime.now() + timedelta(seconds=ban_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE users SET banned_until=? WHERE api_key=?", (banned_until, api_key))
    conn.commit()
    return ban_seconds

# --- IP Sliding-window limiter ---
def is_ip_allowed(ip):
    now = time.time()
    # check in-memory banned list first
    with banned_ips_lock:
        ban_until = banned_ips.get(ip)
        if ban_until and now < ban_until:
            return False, int(ban_until - now)

    # sliding window: drop timestamps older than WINDOW_IP
    with ip_lock:
        dq = ip_requests[ip]
        while dq and dq[0] <= now - WINDOW_IP:
            dq.popleft()
        if len(dq) < RATE_LIMIT_IP:
            dq.append(now)
            return True, None
        else:
            # temporarily ban IP for a small cooldown (avoid rechecks every second)
            ban_seconds = TEMP_BAN_SECONDS
            ban_until = now + ban_seconds
            with banned_ips_lock:
                banned_ips[ip] = ban_until
            return False, ban_seconds

# --- Rate limiting logic for API key (fixed-window) ---
def is_key_allowed(api_key):
    user = get_or_create_user(api_key)
    user_id, key, count, window_start, blocked, banned_until = user

    # check blocked/banned status
    banned, reason = is_key_banned(user)
    if banned:
        return False, reason

    # ensure proper datetime parsing and total_seconds
    try:
        window_start_dt = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()

    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()

    if elapsed >= WINDOW_SIZE:
        # reset window
        cursor.execute("UPDATE users SET request_count=?, window_start_time=? WHERE api_key=?",
                       (1, now.strftime("%Y-%m-%d %H:%M:%S"), api_key))
        conn.commit()
        return True, None
    else:
        if count < RATE_LIMIT_KEY:
            cursor.execute("UPDATE users SET request_count=? WHERE api_key=?",
                           (count + 1, api_key))
            conn.commit()
            return True, None
        else:
            # exceed => ban the key temporarily and escalate
            ban_seconds = ban_key(api_key)
            return False, ban_seconds

# --- Combined check used by endpoints ---
def allow_request(api_key):
    ip = request.remote_addr or "unknown"
    # 1) Check IP level
    ip_ok, ip_info = is_ip_allowed(ip)
    if not ip_ok:
        return False, {"type": "ip", "retry_after": int(ip_info)}

    # 2) Check API key provided
    if not api_key:
        return False, {"type": "auth", "message": "api key required"}

    # 3) Check API key level
    key_ok, key_info = is_key_allowed(api_key)
    if not key_ok:
        # key_info may be "permanently blocked" or seconds to unban
        if isinstance(key_info, (int, float)):
            return False, {"type": "key", "retry_after": int(key_info)}
        else:
            return False, {"type": "key", "message": str(key_info)}

    return True, None

# --- API Endpoints ---
@app.route('/')
def home():
    return jsonify({"message": "🚀 Welcome to upgraded API Rate Limiter! Use /data, /usage, /admin, /logs"})


@app.route('/data')
def get_data():
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"

    allowed, info = allow_request(api_key)

    if allowed:
        status = 200
        body = {"message": "✅ Here’s your protected data!"}
    else:
        # determine response depending on info
        if info and info.get("type") == "auth":
            status = 400
            body = {"error": info.get("message", "API key required")}
        elif info and info.get("type") == "ip":
            status = 429
            reset = info.get("retry_after", WINDOW_IP)
            body = {"error": "⛔ IP rate limit exceeded. Try later.", "retry_after_seconds": reset}
        elif info and info.get("type") == "key":
            if "retry_after" in info:
                status = 429
                reset = info["retry_after"]
                body = {"error": "⛔ API key rate limit exceeded or temporarily banned.", "retry_after_seconds": reset}
            else:
                status = 403
                body = {"error": f"⛔ API key blocked or banned: {info.get('message')}"}
        else:
            status = 429
            body = {"error": "⛔ Rate limit exceeded. Try later."}

    # Log with status and IP (log after decision)
    log_request(api_key, "/data", status, ip)

    # include Retry-After header for 429
    headers = {}
    if status == 429:
        retry = body.get("retry_after_seconds", WINDOW_SIZE)
        headers["Retry-After"] = str(retry)

    return jsonify(body), status, headers


@app.route('/usage')
def usage():
    api_key = request.args.get("api_key")
    ip = request.remote_addr or "unknown"

    # minimal logging + current usage snapshot based on DB values
    if not api_key:
        log_request(None, "/usage", 400, ip)
        return jsonify({"error": "API key required"}), 400

    user = get_or_create_user(api_key)
    _, _, count, window_start, blocked, banned_until = user
    try:
        window_start_dt = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
    except Exception:
        window_start_dt = datetime.now()
    now = datetime.now()
    elapsed = (now - window_start_dt).total_seconds()
    reset_in = max(0, int(WINDOW_SIZE - elapsed))
    requests_left = max(0, RATE_LIMIT_KEY - count)

    log_request(api_key, "/usage", 200, ip)
    return jsonify({
        "requests_left": requests_left,
        "reset_in_seconds": reset_in,
        "blocked": bool(blocked),
        "banned_until": banned_until
    })


# Admin endpoint: lists users and bans (note: protect in production)
@app.route('/admin')
def admin():
    cursor.execute("SELECT api_key, request_count, window_start_time, blocked, banned_until FROM users")
    users = cursor.fetchall()
    ip = request.remote_addr or "unknown"
    log_request("admin", "/admin", 200, ip)
    return jsonify({
        "users": [
            {"api_key": u[0], "request_count": u[1], "window_start_time": u[2], "blocked": bool(u[3]), "banned_until": u[4]}
            for u in users
        ]
    })

# Simple admin controls to block/unblock api keys and IPs
@app.route('/admin/block_key', methods=['POST'])
def admin_block_key():
    data = request.json or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    cursor.execute("UPDATE users SET blocked=1 WHERE api_key=?", (api_key,))
    conn.commit()
    return jsonify({"status": "ok", "message": f"{api_key} blocked"})


@app.route('/admin/unblock_key', methods=['POST'])
def admin_unblock_key():
    data = request.json or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    cursor.execute("UPDATE users SET blocked=0, banned_until=NULL WHERE api_key=?", (api_key,))
    conn.commit()
    with key_ban_lock:
        key_ban_counts.pop(api_key, None)
    return jsonify({"status": "ok", "message": f"{api_key} unblocked"})


@app.route('/admin/block_ip', methods=['POST'])
def admin_block_ip():
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    until = time.time() + 24 * 3600  # block for 24 hours via in-memory list
    with banned_ips_lock:
        banned_ips[ip] = until
    return jsonify({"status": "ok", "message": f"{ip} blocked (in-memory, 24h)"})


@app.route('/logs')
def logs():
    cursor.execute("SELECT api_key, endpoint, status_code, ip, timestamp FROM logs ORDER BY timestamp DESC LIMIT 50")
    logs = cursor.fetchall()
    ip = request.remote_addr or "unknown"
    log_request("admin", "/logs", 200, ip)
    return jsonify({
        "logs": [
            {"api_key": l[0], "endpoint": l[1], "status_code": l[2], "ip": l[3], "timestamp": l[4]}
            for l in logs
        ]
    })


if __name__ == '__main__':
    # For quick local testing only. Use a production WSGI server (gunicorn/uvicorn) behind a proxy in production.
    app.run(debug=True, host='0.0.0.0', port=5000)
# Note: In production, ensure to handle DB connections properly (e.g., connection pooling)
# and secure the admin endpoints with authentication.