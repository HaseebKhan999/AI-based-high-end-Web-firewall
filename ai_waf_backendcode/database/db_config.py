"""
Database Configuration for AI-WAF (Python 3.14 Compatible)
Person 2: Database Manager
SQLite Database (Local - No Network Required)
Compatible with original psycopg2 interface
"""

import os
import sqlite3
import json
from dotenv import load_dotenv
import logging
from contextlib import contextmanager
from datetime import datetime

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration - SQLite
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'ai_waf.db')

# Ensure data directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Global connection pool simulation
connection_pool = None


class DictRow(sqlite3.Row):
    """Custom Row class that behaves like psycopg2 RealDictCursor"""
    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(key)
        return self[self.keys().index(key)]
    
    def __iter__(self):
        for key in self.keys():
            yield key
    
    def keys(self):
        return super().keys()
    
    def values(self):
        return [self[key] for key in self.keys()]
    
    def items(self):
        return [(key, self[key]) for key in self.keys()]


def init_connection_pool():
    """Initialize database connection pool (SQLite - always available)"""
    global connection_pool
    try:
        # SQLite doesn't need a pool, but we simulate for compatibility
        connection_pool = True
        logger.info("✅ Database connection pool created successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to create connection pool: {e}")
        return False


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    
    Usage:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM traffic_logs")
                results = cur.fetchall()
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = DictRow
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()


@contextmanager
def get_db_cursor(commit=True):
    """
    Context manager for database cursor with automatic commit/rollback.
    Returns results as dictionaries (compatible with RealDictCursor).
    
    Usage:
        with get_db_cursor() as cur:
            cur.execute("SELECT * FROM traffic_logs WHERE id = ?", (1,))
            result = cur.fetchone()
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()


def test_connection():
    """Test database connection"""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            result = cur.fetchone()
            cur.close()
        logger.info("✅ Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection test failed: {e}")
        return False


def init_db():
    """Initialize database by creating all tables"""
    try:
        with get_db_cursor() as cur:
            # Create traffic_logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    headers TEXT,
                    body TEXT,
                    query_params TEXT,
                    threat_score REAL DEFAULT 0.0,
                    is_blocked INTEGER DEFAULT 0,
                    attack_type TEXT,
                    features TEXT,
                    response_time REAL
                )
            """)
            
            # Create attack_patterns table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT NOT NULL UNIQUE,
                    pattern_regex TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create whitelist table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create blacklist table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                )
            """)
            
            # Create waf_config table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS waf_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key TEXT NOT NULL UNIQUE,
                    config_value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create ml_models table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ml_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    accuracy REAL,
                    file_path TEXT,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(model_name, model_version)
                )
            """)
            
            # Create indexes for better performance
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp 
                ON traffic_logs(timestamp DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_logs_ip 
                ON traffic_logs(ip_address)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_logs_blocked 
                ON traffic_logs(is_blocked)
            """)
            
            logger.info("✅ Database tables created successfully")
            
            # Insert default configuration
            _insert_default_config(cur)
            
        return True
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        return False


def _insert_default_config(cur):
    """Insert default WAF configuration"""
    default_configs = [
        ('threat_threshold', '0.7'),
        ('enable_blocking', 'true'),
        ('enable_logging', 'true'),
        ('rate_limit_enabled', 'true'),
        ('rate_limit_requests', '100'),
        ('rate_limit_window', '60'),
        ('enable_anomaly_detection', 'true'),
        ('log_retention_days', '30')
    ]
    
    for key, value in default_configs:
        cur.execute("""
            INSERT OR IGNORE INTO waf_config (config_key, config_value)
            VALUES (?, ?)
        """, (key, value))
    
    logger.info("✅ Default configuration inserted")


def close_db():
    """Close all database connections"""
    global connection_pool
    if connection_pool:
        connection_pool = None
        logger.info("✅ Database connections closed")


# Helper functions for JSON handling (SQLite stores JSON as TEXT)
def json_to_text(data):
    """Convert Python dict/list to JSON string for SQLite storage"""
    if data is None:
        return None
    return json.dumps(data)


def text_to_json(text):
    """Convert JSON string from SQLite to Python dict/list"""
    if text is None:
        return None
    try:
        return json.loads(text)
    except:
        return None


if __name__ == "__main__":
    """Test database connection"""
    print("\n" + "="*50)
    print("🔧 Testing SQLite Database Connection")
    print("="*50 + "\n")
    
    # Initialize connection pool
    if init_connection_pool():
        print("✅ Connection pool created")
        
        # Test connection
        if test_connection():
            print("✅ SUCCESS: Connected to SQLite database!")
            print(f"✅ Database location: {DB_PATH}")
            
            # Initialize tables
            print("\n📊 Creating database tables...")
            if init_db():
                print("✅ Database initialized successfully!")
                
                # Show table count
                with get_db_cursor() as cur:
                    cur.execute("""
                        SELECT COUNT(*) as count 
                        FROM sqlite_master 
                        WHERE type='table' AND name NOT LIKE 'sqlite_%'
                    """)
                    result = cur.fetchone()
                    print(f"✅ Total tables created: {result['count']}")
                    
                    # List all tables
                    cur.execute("""
                        SELECT name FROM sqlite_master 
                        WHERE type='table' AND name NOT LIKE 'sqlite_%'
                        ORDER BY name
                    """)
                    tables = cur.fetchall()
                    print("\n📋 Tables created:")
                    for table in tables:
                        print(f"   - {table['name']}")
            
        else:
            print("❌ FAILED: Could not connect to database")
    else:
        print("❌ FAILED: Could not create connection pool")
    
    print("\n" + "="*50)
    
    # Close connections
    close_db()