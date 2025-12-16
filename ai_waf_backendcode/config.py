"""
Configuration Settings for AI-WAF
Centralized configuration management
Python 3.14 Compatible

All team members use this file for configuration settings
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent


# ============================================================================
# FLASK APPLICATION SETTINGS
# ============================================================================

class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'ai-waf-secret-key-change-in-production-please')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    TESTING = False
    
    # Server settings
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # Request settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max request size
    JSON_SORT_KEYS = False
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']


# ============================================================================
# DATABASE CONFIGURATION (Person 2)
# ============================================================================

class DatabaseConfig:
    """Database configuration settings for SQLite"""
    
    # SQLite database path
    DB_PATH = BASE_DIR / 'data' / 'ai_waf.db'
    
    # Ensure data directory exists
    DB_PATH.parent.mkdir(exist_ok=True)
    
    # Database file path as string (for compatibility)
    DATABASE_URL = f"sqlite:///{DB_PATH}"
    
    # SQLite doesn't need connection pooling
    # These are kept for compatibility but not used
    DB_POOL_MIN = 1
    DB_POOL_MAX = 1
    
    # Query timeout (seconds) - SQLite handles this differently
    DB_QUERY_TIMEOUT = int(os.getenv('DB_QUERY_TIMEOUT', 30))
    
    # Log retention (days)
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', 30))


# ============================================================================
# WAF CONFIGURATION (Person 1)
# ============================================================================

class WAFConfig:
    """WAF protection settings"""
    
    # Threat detection threshold (0.0 to 1.0)
    # Requests with threat_score > threshold will be blocked
    THREAT_THRESHOLD = float(os.getenv('THREAT_THRESHOLD', 0.7))
    
    # Enable/disable WAF protection
    ENABLE_WAF = os.getenv('ENABLE_WAF', 'True').lower() == 'true'
    
    # Enable/disable request blocking
    ENABLE_BLOCKING = os.getenv('ENABLE_BLOCKING', 'True').lower() == 'true'
    
    # Enable/disable request logging
    ENABLE_LOGGING = os.getenv('ENABLE_LOGGING', 'True').lower() == 'true'
    
    # Rate limiting settings
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', 100))  # requests per window
    RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60))  # seconds
    
    # Paths exempt from WAF protection
    EXEMPT_PATHS = [
        '/health',
        '/docs',
        '/api/admin',
        '/static',
        '/'
    ]
    
    # IP whitelist (always allowed)
    DEFAULT_WHITELIST = ['127.0.0.1', 'localhost', '::1']
    
    # IP blacklist (always blocked)
    DEFAULT_BLACKLIST = []


# ============================================================================
# ML MODEL CONFIGURATION (Person 3)
# ============================================================================

class MLConfig:
    """Machine Learning model settings"""
    
    # Model paths
    MODELS_DIR = BASE_DIR / 'data' / 'trained_models'
    DATASETS_DIR = BASE_DIR / 'data' / 'datasets'
    
    # Random Forest model
    RF_MODEL_PATH = MODELS_DIR / 'random_forest_model.pkl'
    RF_MODEL_METADATA = MODELS_DIR / 'random_forest_model_metadata.json'
    
    # Isolation Forest model
    IF_MODEL_PATH = MODELS_DIR / 'isolation_forest_model.pkl'
    IF_MODEL_METADATA = MODELS_DIR / 'isolation_forest_model_metadata.json'
    
    # Feature scaler
    SCALER_PATH = MODELS_DIR / 'scaler.pkl'
    
    # Training dataset
    TRAINING_DATA_PATH = DATASETS_DIR / 'csic_database.csv'
    
    # Enable/disable ML-based detection
    ENABLE_ML_DETECTION = os.getenv('ENABLE_ML_DETECTION', 'True').lower() == 'true'
    
    # Enable/disable anomaly detection
    ENABLE_ANOMALY_DETECTION = os.getenv('ENABLE_ANOMALY_DETECTION', 'True').lower() == 'true'
    
    # ML model training parameters
    RANDOM_FOREST_PARAMS = {
        'n_estimators': int(os.getenv('RF_N_ESTIMATORS', 100)),
        'max_depth': int(os.getenv('RF_MAX_DEPTH', 20)),
        'min_samples_split': int(os.getenv('RF_MIN_SAMPLES_SPLIT', 5)),
        'min_samples_leaf': int(os.getenv('RF_MIN_SAMPLES_LEAF', 2)),
        'max_features': os.getenv('RF_MAX_FEATURES', 'sqrt'),
        'random_state': 42,
        'n_jobs': -1,
        'class_weight': 'balanced'
    }
    
    ISOLATION_FOREST_PARAMS = {
        'n_estimators': int(os.getenv('IF_N_ESTIMATORS', 100)),
        'contamination': float(os.getenv('IF_CONTAMINATION', 0.1)),
        'random_state': 42,
        'n_jobs': -1
    }
    
    # Feature extraction settings
    NUM_FEATURES = 20  # Total number of features extracted
    
    # Training settings
    TEST_SIZE = float(os.getenv('ML_TEST_SIZE', 0.2))  # 20% test split
    VALIDATION_SIZE = float(os.getenv('ML_VALIDATION_SIZE', 0.1))  # 10% validation split


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

class LoggingConfig:
    """Logging settings"""
    
    # Log directory
    LOG_DIR = BASE_DIR / 'logs'
    LOG_FILE = LOG_DIR / 'app.log'
    
    # Ensure log directory exists
    LOG_DIR.mkdir(exist_ok=True)
    
    # Log level
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Log format
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    # Log rotation settings
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5  # Keep 5 backup files
    
    # Console logging
    ENABLE_CONSOLE_LOGGING = True
    
    # File logging
    ENABLE_FILE_LOGGING = os.getenv('ENABLE_FILE_LOGGING', 'True').lower() == 'true'


# ============================================================================
# API CONFIGURATION (Person 2)
# ============================================================================

class APIConfig:
    """API settings"""
    
    # API version
    API_VERSION = '1.0.0'
    
    # API prefix
    API_PREFIX = '/api'
    
    # Admin API prefix
    ADMIN_PREFIX = '/api/admin'
    
    # Traffic API prefix
    TRAFFIC_PREFIX = '/api/traffic'
    
    # Pagination defaults
    DEFAULT_PAGE_SIZE = int(os.getenv('DEFAULT_PAGE_SIZE', 100))
    MAX_PAGE_SIZE = int(os.getenv('MAX_PAGE_SIZE', 500))
    
    # Request timeout (seconds)
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))
    
    # Enable/disable API documentation
    ENABLE_API_DOCS = os.getenv('ENABLE_API_DOCS', 'True').lower() == 'true'


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

class SecurityConfig:
    """Security settings"""
    
    # Authentication (optional - add if needed)
    ENABLE_AUTHENTICATION = os.getenv('ENABLE_AUTHENTICATION', 'False').lower() == 'true'
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
    
    # API key authentication (optional)
    ENABLE_API_KEY_AUTH = os.getenv('ENABLE_API_KEY_AUTH', 'False').lower() == 'true'
    API_KEY = os.getenv('API_KEY')
    
    # Rate limiting for API endpoints
    API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100 per minute')
    
    # HTTPS enforcement (for production)
    FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'False').lower() == 'true'


# ============================================================================
# ATTACK DETECTION PATTERNS (Person 1)
# ============================================================================

class AttackPatternsConfig:
    """Attack detection patterns and signatures"""
    
    # SQL Injection patterns
    SQL_INJECTION_KEYWORDS = [
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'create', 'alter', 'exec', 'execute', 'script', 'javascript',
        'concat', 'char', 'varchar', 'syscolumns', 'sysobjects',
        'xp_', 'sp_', 'declare', 'cast', 'convert'
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
        'onclick=', 'onmouseover=', '<iframe', 'alert(', 'prompt(',
        'confirm(', 'document.cookie', 'document.write', 'eval('
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        '../', '..\\', '..%2f', '..%5c', '%2e%2e/',
        '..../', './../', 'etc/passwd', 'windows/system32'
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_CHARS = [';', '|', '&', '`', '$', '(', ')', '\n', '\r']


# ============================================================================
# DEVELOPMENT & PRODUCTION CONFIGURATIONS
# ============================================================================

class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development (optional)
    # DATABASE_URL = 'sqlite:///dev_database.db'


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    TESTING = False
    
    # Security settings for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Enforce HTTPS
    PREFERRED_URL_SCHEME = 'https'


class TestingConfig(Config):
    """Testing environment configuration"""
    DEBUG = True
    TESTING = True
    
    # Use in-memory SQLite for testing
    DATABASE_URL = 'sqlite:///:memory:'


# ============================================================================
# CONFIGURATION SELECTOR
# ============================================================================

# Environment selector
ENV = os.getenv('FLASK_ENV', 'development').lower()

config_by_env = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}

# Select configuration based on environment
CurrentConfig = config_by_env.get(ENV, DevelopmentConfig)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_config():
    """Get current configuration"""
    return CurrentConfig


def get_database_config():
    """Get database configuration"""
    return DatabaseConfig


def get_waf_config():
    """Get WAF configuration"""
    return WAFConfig


def get_ml_config():
    """Get ML configuration"""
    return MLConfig


def get_logging_config():
    """Get logging configuration"""
    return LoggingConfig


def get_api_config():
    """Get API configuration"""
    return APIConfig


def get_security_config():
    """Get security configuration"""
    return SecurityConfig


def print_config():
    """Print current configuration (for debugging)"""
    print("\n" + "="*70)
    print("🔧 AI-WAF CONFIGURATION")
    print("="*70)
    print(f"\n🌍 Environment: {ENV.upper()}")
    print(f"🐛 Debug Mode: {CurrentConfig.DEBUG}")
    print(f"🏠 Host: {CurrentConfig.HOST}")
    print(f"🔌 Port: {CurrentConfig.PORT}")
    
    print(f"\n💾 Database:")
    print(f"   Type: SQLite")
    print(f"   Path: {DatabaseConfig.DB_PATH}")
    print(f"   URL: {DatabaseConfig.DATABASE_URL}")
    
    print(f"\n🛡️ WAF:")
    print(f"   Enabled: {WAFConfig.ENABLE_WAF}")
    print(f"   Blocking: {WAFConfig.ENABLE_BLOCKING}")
    print(f"   Threshold: {WAFConfig.THREAT_THRESHOLD}")
    
    print(f"\n🤖 ML Models:")
    print(f"   ML Detection: {MLConfig.ENABLE_ML_DETECTION}")
    print(f"   Anomaly Detection: {MLConfig.ENABLE_ANOMALY_DETECTION}")
    print(f"   Models Dir: {MLConfig.MODELS_DIR}")
    
    print(f"\n📊 API:")
    print(f"   Version: {APIConfig.API_VERSION}")
    print(f"   Page Size: {APIConfig.DEFAULT_PAGE_SIZE}")
    
    print("\n" + "="*70 + "\n")


# Test configuration
if __name__ == "__main__":
    print_config()
    
    # Test paths
    print("📁 Path Configuration:")
    print(f"   Base Dir: {BASE_DIR}")
    print(f"   Models Dir: {MLConfig.MODELS_DIR}")
    print(f"   Datasets Dir: {MLConfig.DATASETS_DIR}")
    print(f"   Log Dir: {LoggingConfig.LOG_DIR}")
    
    # Check if model files exist
    print(f"\n🔍 Model Files Check:")
    print(f"   RF Model: {'✅ Exists' if MLConfig.RF_MODEL_PATH.exists() else '❌ Not Found'}")
    print(f"   IF Model: {'✅ Exists' if MLConfig.IF_MODEL_PATH.exists() else '❌ Not Found'}")
    print(f"   Scaler: {'✅ Exists' if MLConfig.SCALER_PATH.exists() else '❌ Not Found'}")
    print(f"   Training Data: {'✅ Exists' if MLConfig.TRAINING_DATA_PATH.exists() else '❌ Not Found'}")