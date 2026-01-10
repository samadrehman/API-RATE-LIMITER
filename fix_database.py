import sqlite3
import os

def migrate_database():
    """Migrate existing database to new schema"""
    
    db_path = 'ratelimiter.db'
    
    print("🔧 Database Migration Tool")
    print("=" * 60)
    
    if not os.path.exists(db_path):
        print(f"❌ Database file '{db_path}' not found!")
        print("Creating new database with correct schema...")
        create_fresh_database()
        return
    
    # Backup the old database
    backup_path = 'ratelimiter.db.backup'
    if os.path.exists(db_path):
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✅ Backup created: {backup_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check current schema
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    print(f"\nCurrent columns: {columns}")
    
    # Add missing columns
    columns_to_add = [
        ('blocked', 'INTEGER DEFAULT 0'),
        ('banned_until', 'TEXT DEFAULT NULL'),
        ('tier', "TEXT DEFAULT 'free'"),
        ('total_requests', 'INTEGER DEFAULT 0'),
        ('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    ]
    
    for col_name, col_def in columns_to_add:
        if col_name not in columns:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
                print(f"✅ Added column: {col_name}")
            except sqlite3.OperationalError as e:
                print(f"⚠️  Column {col_name} might already exist: {e}")
    
    # Check logs table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(logs)")
        log_columns = [row[1] for row in cursor.fetchall()]
        
        # Add missing log columns
        log_columns_to_add = [
            ('user_agent', 'TEXT'),
            ('response_time_ms', 'INTEGER')
        ]
        
        for col_name, col_def in log_columns_to_add:
            if col_name not in log_columns:
                try:
                    cursor.execute(f"ALTER TABLE logs ADD COLUMN {col_name} {col_def}")
                    print(f"✅ Added log column: {col_name}")
                except sqlite3.OperationalError as e:
                    print(f"⚠️  Column {col_name} might already exist: {e}")
    
    # Create analytics table if not exists
    cursor.execute("""CREATE TABLE IF NOT EXISTS analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_type TEXT NOT NULL,
                        metric_value REAL,
                        metadata TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    print("✅ Analytics table ready")
    
    # Create indexes
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_api_key ON logs(api_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics(timestamp)")
        print("✅ Indexes created")
    except Exception as e:
        print(f"⚠️  Index creation: {e}")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 60)
    print("✅ Migration completed successfully!")
    print("=" * 60)
    print("\n🚀 You can now run: python app.py")


def create_fresh_database():
    """Create a fresh database with correct schema"""
    
    db_path = 'ratelimiter.db'
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Drop existing tables
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS logs")
    cursor.execute("DROP TABLE IF EXISTS analytics")
    
    # Create users table with all columns
    cursor.execute("""CREATE TABLE users (
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
    
    # Create logs table
    cursor.execute("""CREATE TABLE logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        status_code INTEGER,
                        ip TEXT,
                        user_agent TEXT,
                        response_time_ms INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    
    # Create analytics table
    cursor.execute("""CREATE TABLE analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_type TEXT NOT NULL,
                        metric_value REAL,
                        metadata TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )""")
    
    # Create indexes
    cursor.execute("CREATE INDEX idx_logs_timestamp ON logs(timestamp)")
    cursor.execute("CREATE INDEX idx_logs_api_key ON logs(api_key)")
    cursor.execute("CREATE INDEX idx_analytics_timestamp ON analytics(timestamp)")
    
    conn.commit()
    conn.close()
    
    print("✅ Fresh database created with correct schema!")


def check_database():
    """Check and display database schema"""
    
    db_path = 'ratelimiter.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Database '{db_path}' not found!")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n📊 Database Schema Check")
    print("=" * 60)
    
    # Check users table
    print("\n👥 USERS TABLE:")
    cursor.execute("PRAGMA table_info(users)")
    for row in cursor.fetchall():
        print(f"  • {row[1]} ({row[2]})")
    
    # Check logs table
    print("\n📝 LOGS TABLE:")
    cursor.execute("PRAGMA table_info(logs)")
    for row in cursor.fetchall():
        print(f"  • {row[1]} ({row[2]})")
    
    # Check analytics table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analytics'")
    if cursor.fetchone():
        print("\n📈 ANALYTICS TABLE:")
        cursor.execute("PRAGMA table_info(analytics)")
        for row in cursor.fetchall():
            print(f"  • {row[1]} ({row[2]})")
    
    # Count records
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    log_count = cursor.fetchone()[0]
    
    print("\n" + "=" * 60)
    print(f"📊 Records: {user_count} users, {log_count} logs")
    print("=" * 60)
    
    conn.close()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        check_database()
    elif len(sys.argv) > 1 and sys.argv[1] == "fresh":
        print("⚠️  WARNING: This will DELETE all existing data!")
        confirm = input("Type 'yes' to continue: ")
        if confirm.lower() == 'yes':
            create_fresh_database()
        else:
            print("Cancelled.")
    else:
        migrate_database()
        print("\n💡 Run with 'check' to view schema: python fix_database.py check")