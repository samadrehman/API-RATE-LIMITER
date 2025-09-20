import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Database connection ---
conn = sqlite3.connect('ratelimiter.db', check_same_thread=False)
cursor = conn.cursor()

# --- Config ---
RATE_LIMIT = 5      # max requests
WINDOW_SIZE = 60    # seconds

# --- Helper: Log each request ---
def log_request(api_key, endpoint):
    cursor.execute("INSERT INTO logs (api_key, endpoint) VALUES (?, ?)", (api_key, endpoint))
    conn.commit()

# --- Helper function to get/create user ---
def get_or_create_user(api_key):
    cursor.execute("SELECT * FROM users WHERE api_key=?", (api_key,))
    user = cursor.fetchone()
    if not user:
        cursor.execute("INSERT INTO users (api_key, request_count, window_start_time) VALUES (?, ?, ?)",
                       (api_key, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE api_key=?", (api_key,))
        user = cursor.fetchone()
    return user

# --- Rate limiting logic ---
def is_request_allowed(api_key):
    user = get_or_create_user(api_key)
    user_id, key, count, window_start = user
    window_start = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")

    now = datetime.now()
    if (now - window_start).seconds >= WINDOW_SIZE:
        cursor.execute("UPDATE users SET request_count=?, window_start_time=? WHERE api_key=?",
                       (1, now.strftime("%Y-%m-%d %H:%M:%S"), api_key))
        conn.commit()
        return True
    else:
        if count < RATE_LIMIT:
            cursor.execute("UPDATE users SET request_count=? WHERE api_key=?",
                           (count + 1, api_key))
            conn.commit()
            return True
        else:
            return False

# --- API Endpoints ---

@app.route('/')
def home():
    return jsonify({"message": "🚀 Welcome to API Rate Limiter! Use /data, /usage, /admin, or /logs"})

# Protected data
@app.route('/data')
def get_data():
    api_key = request.args.get("api_key")
    if not api_key:
        return jsonify({"error": "API key required"}), 400

    log_request(api_key, "/data")

    if is_request_allowed(api_key):
        return jsonify({"message": "✅ Here’s your protected data!"})
    else:
        return jsonify({"error": "⛔ Rate limit exceeded. Try later."}), 429

# Usage endpoint
@app.route('/usage')
def usage():
    api_key = request.args.get("api_key")
    if not api_key:
        return jsonify({"error": "API key required"}), 400

    log_request(api_key, "/usage")

    user = get_or_create_user(api_key)
    _, _, count, window_start = user
    window_start = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")

    now = datetime.now()
    elapsed = (now - window_start).seconds
    reset_in = max(0, WINDOW_SIZE - elapsed)
    requests_left = max(0, RATE_LIMIT - count)

    return jsonify({
        "requests_left": requests_left,
        "reset_in_seconds": reset_in
    })

# Admin endpoint
@app.route('/admin')
def admin():
    cursor.execute("SELECT api_key, request_count, window_start_time FROM users")
    users = cursor.fetchall()
    log_request("admin", "/admin")
    return jsonify({
        "users": [
            {"api_key": u[0], "request_count": u[1], "window_start_time": u[2]}
            for u in users
        ]
    })

# Logs endpoint
@app.route('/logs')
def logs():
    cursor.execute("SELECT api_key, endpoint, timestamp FROM logs ORDER BY timestamp DESC LIMIT 20")
    logs = cursor.fetchall()
    return jsonify({
        "logs": [
            {"api_key": l[0], "endpoint": l[1], "timestamp": l[2]}
            for l in logs
        ]
    })

if __name__ == '__main__':
    app.run(debug=True)
