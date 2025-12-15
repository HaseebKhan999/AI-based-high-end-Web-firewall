"""
Database Configuration for AI-WAF (Python 3.14 Compatible)
Person 2: Database Manager
Neon PostgreSQL Database Connection
Using psycopg2 directly (no SQLAlchemy ORM)
"""

import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import logging
from contextlib import contextmanager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')

if not DATABASE_URL:
    # Construct from individual components
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME')
    
    if all([DB_USER, DB_PASSWORD, DB_HOST, DB_NAME]):
        DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode=require"
    else:
        raise ValueError("Database configuration not found in .env file")

# Connection pool for efficient database connections
connection_pool = None


def init_connection_pool():
    """Initialize database connection pool"""
    global connection_pool
    try:
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=DATABASE_URL
        )
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
        if connection_pool is None:
            init_connection_pool()
        
        conn = connection_pool.getconn()
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            connection_pool.putconn(conn)


@contextmanager
def get_db_cursor(commit=True):
    """
    Context manager for database cursor with automatic commit/rollback.
    Returns results as dictionaries.
    
    Usage:
        with get_db_cursor() as cur:
            cur.execute("SELECT * FROM traffic_logs WHERE id = %s", (1,))
            result = cur.fetchone()
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
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
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                result = cur.fetchone()
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
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45) NOT NULL,
                    method VARCHAR(10) NOT NULL,
                    url TEXT NOT NULL,
                    headers JSONB,
                    body TEXT,
                    query_params JSONB,
                    threat_score FLOAT DEFAULT 0.0,
                    is_blocked BOOLEAN DEFAULT FALSE,
                    attack_type VARCHAR(100),
                    features JSONB,
                    response_time FLOAT
                )
            """)
            
            # Create attack_patterns table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id SERIAL PRIMARY KEY,
                    pattern_name VARCHAR(100) NOT NULL UNIQUE,
                    pattern_regex TEXT NOT NULL,
                    severity VARCHAR(20) DEFAULT 'medium',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create whitelist table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id SERIAL PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    reason TEXT,
                    added_by VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create blacklist table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    reason TEXT,
                    added_by VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            
            # Create waf_config table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS waf_config (
                    id SERIAL PRIMARY KEY,
                    config_key VARCHAR(100) NOT NULL UNIQUE,
                    config_value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create ml_models table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ml_models (
                    id SERIAL PRIMARY KEY,
                    model_name VARCHAR(100) NOT NULL,
                    model_version VARCHAR(20) NOT NULL,
                    accuracy FLOAT,
                    file_path TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
            INSERT INTO waf_config (config_key, config_value)
            VALUES (%s, %s)
            ON CONFLICT (config_key) DO NOTHING
        """, (key, value))
    
    logger.info("✅ Default configuration inserted")


def close_db():
    """Close all database connections"""
    global connection_pool
    if connection_pool:
        connection_pool.closeall()
        logger.info("✅ Database connections closed")


if __name__ == "__main__":
    """Test database connection"""
    print("\n" + "="*50)
    print("🔧 Testing Neon Database Connection")
    print("="*50 + "\n")
    
    # Initialize connection pool
    if init_connection_pool():
        print("✅ Connection pool created")
        
        # Test connection
        if test_connection():
            print("✅ SUCCESS: Connected to Neon database!")
            
            # Initialize tables
            print("\n📊 Creating database tables...")
            if init_db():
                print("✅ Database initialized successfully!")
                
                # Show table count
                with get_db_cursor() as cur:
                    cur.execute("""
                        SELECT COUNT(*) as count 
                        FROM information_schema.tables 
                        WHERE table_schema = 'public'
                    """)
                    result = cur.fetchone()
                    print(f"✅ Total tables created: {result['count']}")
            
        else:
            print("❌ FAILED: Could not connect to database")
    else:
        print("❌ FAILED: Could not create connection pool")
    
    print("\n" + "="*50)
    
    # Close connections
    close_db()