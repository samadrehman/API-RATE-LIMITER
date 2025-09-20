import sqlite3

# Connect to database (creates ratelimiter.db if not exists)
conn = sqlite3.connect("ratelimiter.db")
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT UNIQUE NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''')

# Create logs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''')

conn.commit()
conn.close()

print("✅ Database and tables (users + logs) created successfully!")
