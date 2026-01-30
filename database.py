"""
Database Migration Tool for API Rate Limiter

This script handles database schema migrations from old versions to the new
security-hardened version with:
- Automatic schema detection and upgrade
- Safe backup creation before migration
- Support for both plain API key and hashed API key schemas
- Comprehensive error handling and rollback
- Schema validation and verification
- Fresh database creation option

Key Features:
- Backward compatible with existing data
- Creates backups automatically
- Validates schema after migration
- Supports incremental migrations
- Detailed logging of all operations
- Safe rollback on errors

Migration Paths:
1. Old Schema → New Security Schema (with API key hashing)
2. Fresh database creation
3. Schema verification and repair

Usage:
    # Migrate existing database
    python database_migration.py
    
    # Check current schema
    python database_migration.py check
    
    # Create fresh database (WARNING: deletes all data)
    python database_migration.py fresh
    
    # Verify database integrity
    python database_migration.py verify

Requirements:
    - sqlite3 (Python standard library)
    - bcrypt (for API key hashing in production)

Version: 2.0.0
Last Updated: 2026

"""

import sqlite3
import os
import sys
import shutil
from datetime import datetime
from typing import List, Tuple, Optional



DB_PATH = 'ratelimiter.db'
BACKUP_DIR = 'backups'
USE_HASHED_KEYS = True  # Set to True for production security schema



# Old schema (plain text API keys)
OLD_USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT UNIQUE NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked INTEGER DEFAULT 0,
    banned_until TEXT DEFAULT NULL,
    tier TEXT DEFAULT 'free',
    total_requests INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

# New security schema (hashed API keys)
NEW_USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_hash TEXT UNIQUE NOT NULL,
    api_key_prefix TEXT NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked INTEGER DEFAULT 0,
    banned_until TEXT DEFAULT NULL,
    tier TEXT DEFAULT 'free',
    total_requests INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

LOGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_prefix TEXT,
    endpoint TEXT NOT NULL,
    status_code INTEGER,
    ip_hash TEXT,
    user_agent TEXT,
    response_time_ms INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

ANALYTICS_SCHEMA = """
CREATE TABLE IF NOT EXISTS analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_type TEXT NOT NULL,
    metric_value REAL,
    metadata TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

ADMIN_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target_api_key_prefix TEXT,
    admin_ip_hash TEXT,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


# UTILITY FUNCTIONS

def create_backup(db_path: str) -> Optional[str]:
    """
    Create timestamped backup of database
    
    Args:
        db_path: Path to database file
        
    Returns:
        Path to backup file or None if failed
    """
    if not os.path.exists(db_path):
        print(f"⚠️  Database file '{db_path}' not found, no backup needed")
        return None
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"📁 Created backup directory: {BACKUP_DIR}")
    
    # Generate timestamped backup filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"ratelimiter_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    try:
        shutil.copy2(db_path, backup_path)
        print(f"✅ Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to create backup: {str(e)}")
        return None


def get_table_columns(cursor: sqlite3.Cursor, table_name: str) -> List[str]:
    """
    Get list of column names in a table
    
    Args:
        cursor: SQLite cursor
        table_name: Name of table
        
    Returns:
        List of column names
    """
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [row[1] for row in cursor.fetchall()]
    except sqlite3.Error:
        return []


def table_exists(cursor: sqlite3.Cursor, table_name: str) -> bool:
    """
    Check if table exists in database
    
    Args:
        cursor: SQLite cursor
        table_name: Name of table to check
        
    Returns:
        True if table exists, False otherwise
    """
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None


def add_column_if_missing(
    cursor: sqlite3.Cursor,
    table_name: str,
    column_name: str,
    column_def: str
) -> bool:
    """
    Add column to table if it doesn't exist
    
    Args:
        cursor: SQLite cursor
        table_name: Name of table
        column_name: Name of column to add
        column_def: Column definition (e.g., 'INTEGER DEFAULT 0')
        
    Returns:
        True if column was added or already exists, False on error
    """
    columns = get_table_columns(cursor, table_name)
    
    if column_name in columns:
        return True
    
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")
        print(f"  ✅ Added column: {table_name}.{column_name}")
        return True
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Could not add column {column_name}: {str(e)}")
        return False



def migrate_database() -> bool:
    """
    Migrate existing database to new schema
    
    Returns:
        True if migration successful, False otherwise
    """
    print("\n🔧 Database Migration Tool")
    print("=" * 70)
    
    if not os.path.exists(DB_PATH):
        print(f"\n❌ Database file '{DB_PATH}' not found!")
        print("Creating new database with correct schema...")
        return create_fresh_database(use_hashed_keys=USE_HASHED_KEYS)
    
    # Create backup
    backup_path = create_backup(DB_PATH)
    if not backup_path and os.path.exists(DB_PATH):
        print("⚠️  Warning: Could not create backup, but continuing...")
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        print("\n📊 Analyzing current schema...")
        
        if not table_exists(cursor, 'users'):
            print("❌ Users table doesn't exist, creating fresh schema...")
            conn.close()
            return create_fresh_database(use_hashed_keys=USE_HASHED_KEYS)
        
        columns = get_table_columns(cursor, 'users')
        print(f"\nCurrent users table columns: {', '.join(columns)}")
        
        has_plain_keys = 'api_key' in columns
        has_hashed_keys = 'api_key_hash' in columns
        
        if USE_HASHED_KEYS and has_plain_keys and not has_hashed_keys:
            print("\n⚠️  WARNING: Database uses plain text API keys!")
            print("Migration to hashed keys requires manual intervention.")
            print("Users will need to be issued new API keys.")
            print("\nTo migrate to security schema:")
            print("1. Export user data")
            print("2. Create fresh database: python database_migration.py fresh")
            print("3. Re-issue API keys to users")
            conn.close()
            return False
        
        print("\n🔄 Updating users table...")
        
        if has_plain_keys:
            columns_to_add = [
                ('blocked', 'INTEGER DEFAULT 0'),
                ('banned_until', 'TEXT DEFAULT NULL'),
                ('tier', "TEXT DEFAULT 'free'"),
                ('total_requests', 'INTEGER DEFAULT 0'),
                ('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'),
                ('updated_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            ]
        else:
            columns_to_add = [
                ('api_key_prefix', "TEXT DEFAULT ''"),
                ('blocked', 'INTEGER DEFAULT 0'),
                ('banned_until', 'TEXT DEFAULT NULL'),
                ('tier', "TEXT DEFAULT 'free'"),
                ('total_requests', 'INTEGER DEFAULT 0'),
                ('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'),
                ('updated_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            ]
        
        for col_name, col_def in columns_to_add:
            add_column_if_missing(cursor, 'users', col_name, col_def)
        
        # Update logs table
        print("\n🔄 Updating logs table...")
        
        if table_exists(cursor, 'logs'):
            log_columns = get_table_columns(cursor, 'logs')
            
            log_columns_to_add = [
                ('user_agent', 'TEXT'),
                ('response_time_ms', 'INTEGER')
            ]
            
            if USE_HASHED_KEYS:
                if 'ip' in log_columns and 'ip_hash' not in log_columns:
                    print("  ℹ️  Note: Consider renaming 'ip' column to 'ip_hash' manually")
                
                if 'api_key' in log_columns and 'api_key_prefix' not in log_columns:
                    print("  ℹ️  Note: Consider renaming 'api_key' to 'api_key_prefix' manually")
            
            for col_name, col_def in log_columns_to_add:
                add_column_if_missing(cursor, 'logs', col_name, col_def)
        else:
            # Create logs table
            print("  ℹ️  Logs table doesn't exist, creating...")
            cursor.execute(LOGS_SCHEMA)
            print("  ✅ Logs table created")
        
        print("\n🔄 Updating analytics table...")
        if not table_exists(cursor, 'analytics'):
            cursor.execute(ANALYTICS_SCHEMA)
            print("  ✅ Analytics table created")
        else:
            print("  ✅ Analytics table already exists")
        
        print("\n🔄 Updating admin_audit table...")
        if not table_exists(cursor, 'admin_audit'):
            cursor.execute(ADMIN_AUDIT_SCHEMA)
            print("  ✅ Admin audit table created")
        else:
            print("  ✅ Admin audit table already exists")
        
        # Create indexes
        print("\n🔄 Creating indexes...")
        indexes = [
            ("idx_logs_timestamp", "logs", "timestamp"),
            ("idx_analytics_timestamp", "analytics", "timestamp"),
            ("idx_analytics_metric_type", "analytics", "metric_type"),
            ("idx_admin_audit_timestamp", "admin_audit", "timestamp")
        ]
        
        # Add appropriate user/log key index based on schema
        if has_hashed_keys:
            indexes.extend([
                ("idx_users_api_key_hash", "users", "api_key_hash"),
                ("idx_users_tier", "users", "tier"),
                ("idx_logs_api_key_prefix", "logs", "api_key_prefix")
            ])
        else:
            indexes.extend([
                ("idx_users_api_key", "users", "api_key"),
                ("idx_users_tier", "users", "tier"),
                ("idx_logs_api_key", "logs", "api_key")
            ])
        
        for idx_name, table_name, column_name in indexes:
            try:
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table_name}({column_name})"
                )
                print(f"  ✅ Index created: {idx_name}")
            except sqlite3.Error as e:
                print(f"  ⚠️  Could not create index {idx_name}: {str(e)}")
        
        # Commit all changes
        conn.commit()
        
        print("\n" + "=" * 70)
        print("✅ Migration completed successfully!")
        print("=" * 70)
        
        if backup_path:
            print(f"\n💾 Backup saved at: {backup_path}")
        
        print("\n🚀 You can now run: python app_fixed.py")
        
        return True
        
    except sqlite3.Error as e:
        print(f"\n❌ Migration failed: {str(e)}")
        if conn:
            conn.rollback()
        
        if backup_path:
            print(f"\n🔄 Restore from backup: cp {backup_path} {DB_PATH}")
        
        return False
        
    finally:
        if conn:
            conn.close()


def create_fresh_database(use_hashed_keys: bool = True) -> bool:
    """
    Create a fresh database with correct schema
    
    Args:
        use_hashed_keys: Use security schema with hashed keys
        
    Returns:
        True if successful, False otherwise
    """
    print("\n🔧 Creating Fresh Database")
    print("=" * 70)
    
    # Backup existing database if it exists
    if os.path.exists(DB_PATH):
        backup_path = create_backup(DB_PATH)
        if backup_path:
            print(f"✅ Existing database backed up to: {backup_path}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Drop existing tables
        print("\n🗑️  Dropping existing tables...")
        tables = ['users', 'logs', 'analytics', 'admin_audit']
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
            print(f"  ✅ Dropped: {table}")
        
        # Create tables with appropriate schema
        print("\n📦 Creating tables...")
        
        if use_hashed_keys:
            print("  🔐 Using security schema (hashed API keys)")
            cursor.execute(NEW_USERS_SCHEMA)
        else:
            print("  ⚠️  Using plain text schema (development only)")
            cursor.execute(OLD_USERS_SCHEMA)
        
        print("  ✅ Users table created")
        
        cursor.execute(LOGS_SCHEMA)
        print("  ✅ Logs table created")
        
        cursor.execute(ANALYTICS_SCHEMA)
        print("  ✅ Analytics table created")
        
        cursor.execute(ADMIN_AUDIT_SCHEMA)
        print("  ✅ Admin audit table created")
        
        # Create indexes
        print("\n🔍 Creating indexes...")
        
        if use_hashed_keys:
            indexes = [
                "CREATE INDEX idx_users_api_key_hash ON users(api_key_hash)",
                "CREATE INDEX idx_users_tier ON users(tier)",
                "CREATE INDEX idx_logs_timestamp ON logs(timestamp)",
                "CREATE INDEX idx_logs_api_key_prefix ON logs(api_key_prefix)",
                "CREATE INDEX idx_analytics_timestamp ON analytics(timestamp)",
                "CREATE INDEX idx_analytics_metric_type ON analytics(metric_type)",
                "CREATE INDEX idx_admin_audit_timestamp ON admin_audit(timestamp)"
            ]
        else:
            indexes = [
                "CREATE INDEX idx_users_api_key ON users(api_key)",
                "CREATE INDEX idx_users_tier ON users(tier)",
                "CREATE INDEX idx_logs_timestamp ON logs(timestamp)",
                "CREATE INDEX idx_logs_api_key ON logs(api_key)",
                "CREATE INDEX idx_analytics_timestamp ON analytics(timestamp)",
                "CREATE INDEX idx_analytics_metric_type ON analytics(metric_type)"
            ]
        
        for idx_sql in indexes:
            cursor.execute(idx_sql)
        
        print("  ✅ All indexes created")
        
        conn.commit()
        conn.close()
        
        print("\n" + "=" * 70)
        print("✅ Fresh database created successfully!")
        print("=" * 70)
        
        if use_hashed_keys:
            print("\n🔒 Security features enabled:")
            print("  • API keys will be hashed with bcrypt")
            print("  • IP addresses will be anonymized")
            print("  • Admin audit logging enabled")
        
        return True
        
    except sqlite3.Error as e:
        print(f"\n❌ Failed to create database: {str(e)}")
        return False


def check_database() -> None:
    """Check and display database schema and statistics"""
    print("\n📊 Database Schema Check")
    print("=" * 70)
    
    if not os.path.exists(DB_PATH):
        print(f"\n❌ Database '{DB_PATH}' not found!")
        print("Run 'python database_migration.py' to create it.")
        return
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check each table
        tables = ['users', 'logs', 'analytics', 'admin_audit']
        
        for table in tables:
            if table_exists(cursor, table):
                print(f"\n✅ {table.upper()} TABLE:")
                cursor.execute(f"PRAGMA table_info({table})")
                for row in cursor.fetchall():
                    col_id, col_name, col_type, not_null, default, pk = row
                    pk_marker = " [PK]" if pk else ""
                    not_null_marker = " NOT NULL" if not_null else ""
                    default_str = f" DEFAULT {default}" if default else ""
                    print(f"  • {col_name} ({col_type}){pk_marker}{not_null_marker}{default_str}")
            else:
                print(f"\n❌ {table.upper()} TABLE: Not found")
        
        # Count records
        print("\n" + "=" * 70)
        print("📈 DATABASE STATISTICS:")
        
        if table_exists(cursor, 'users'):
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"  • Users: {user_count}")
            
            if user_count > 0:
                cursor.execute("SELECT tier, COUNT(*) FROM users GROUP BY tier")
                print("    By tier:")
                for tier, count in cursor.fetchall():
                    print(f"      - {tier}: {count}")
        
        if table_exists(cursor, 'logs'):
            cursor.execute("SELECT COUNT(*) FROM logs")
            log_count = cursor.fetchone()[0]
            print(f"  • Logs: {log_count}")
        
        if table_exists(cursor, 'analytics'):
            cursor.execute("SELECT COUNT(*) FROM analytics")
            analytics_count = cursor.fetchone()[0]
            print(f"  • Analytics: {analytics_count}")
        
        if table_exists(cursor, 'admin_audit'):
            cursor.execute("SELECT COUNT(*) FROM admin_audit")
            audit_count = cursor.fetchone()[0]
            print(f"  • Admin audit: {audit_count}")
        
        # Check for security features
        print("\n🔒 SECURITY FEATURES:")
        columns = get_table_columns(cursor, 'users')
        
        if 'api_key_hash' in columns:
            print("  ✅ API key hashing enabled")
        else:
            print("  ⚠️  Plain text API keys (not recommended for production)")
        
        if table_exists(cursor, 'admin_audit'):
            print("  ✅ Admin audit logging enabled")
        else:
            print("  ⚠️  No admin audit logging")
        
        log_columns = get_table_columns(cursor, 'logs')
        if 'ip_hash' in log_columns:
            print("  ✅ IP address hashing enabled")
        elif 'ip' in log_columns:
            print("  ⚠️  Plain IP addresses in logs")
        
        print("=" * 70)
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"\n❌ Error checking database: {str(e)}")


def verify_database() -> bool:
    """
    Verify database integrity and schema correctness
    
    Returns:
        True if database is valid, False otherwise
    """
    print("\n🔍 Database Verification")
    print("=" * 70)
    
    if not os.path.exists(DB_PATH):
        print(f"\n❌ Database '{DB_PATH}' not found!")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Run integrity check
        print("\n🔎 Running integrity check...")
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()[0]
        
        if result == "ok":
            print("  ✅ Database integrity: OK")
        else:
            print(f"  ❌ Database integrity: {result}")
            conn.close()
            return False
        
        # Verify required tables exist
        print("\n🔎 Checking required tables...")
        required_tables = ['users', 'logs']
        all_tables_exist = True
        
        for table in required_tables:
            if table_exists(cursor, table):
                print(f"  ✅ {table} table exists")
            else:
                print(f"  ❌ {table} table missing")
                all_tables_exist = False
        
        # Verify indexes
        print("\n🔎 Checking indexes...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row[0] for row in cursor.fetchall()]
        
        if indexes:
            print(f"  ✅ Found {len(indexes)} indexes")
            for idx in indexes:
                if not idx.startswith('sqlite_'):  # Skip auto-generated indexes
                    print(f"    • {idx}")
        else:
            print("  ⚠️  No indexes found (may impact performance)")
        
        print("\n" + "=" * 70)
        
        if all_tables_exist:
            print("✅ Database verification passed!")
        else:
            print("⚠️  Database has issues - consider running migration")
        
        print("=" * 70)
        
        conn.close()
        return all_tables_exist
        
    except sqlite3.Error as e:
        print(f"\n❌ Verification failed: {str(e)}")
        return False


# MAIN

def print_usage():
    """Print usage information"""
    print("\n📚 Database Migration Tool - Usage")
    print("=" * 70)
    print("\nCommands:")
    print("  python database_migration.py          - Migrate existing database")
    print("  python database_migration.py check    - Check database schema")
    print("  python database_migration.py verify   - Verify database integrity")
    print("  python database_migration.py fresh    - Create fresh database (deletes data!)")
    print("  python database_migration.py help     - Show this help message")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "check":
            check_database()
        elif command == "verify":
            verify_database()
        elif command == "fresh":
            print("\n⚠️  WARNING: This will DELETE all existing data!")
            print(f"Database: {DB_PATH}")
            confirm = input("\nType 'YES' (all caps) to continue: ")
            
            if confirm == 'YES':
                use_hashed = input("Use security schema with hashed keys? (y/n): ").lower() == 'y'
                create_fresh_database(use_hashed_keys=use_hashed)
            else:
                print("❌ Operation cancelled.")
        elif command == "help":
            print_usage()
        else:
            print(f"❌ Unknown command: {command}")
            print_usage()
    else:
        # Default: run migration
        success = migrate_database()
        
        if success:
            print("\n💡 Useful commands:")
            print("  python database_migration.py check  - View schema")
            print("  python database_migration.py verify - Verify integrity")