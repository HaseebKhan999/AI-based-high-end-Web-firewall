"""
Database Models for AI-WAF
Person 2: Database Manager
SQLAlchemy model definitions for reference/documentation
Python 3.14 Compatible

NOTE: These models are for REFERENCE ONLY.
The actual database operations use direct SQL queries in db_operations.py
for Python 3.14 compatibility.
"""

from datetime import datetime
from typing import Optional, Dict, List

# This is a reference implementation - not actively used in the application
# The actual tables are created via SQL in db_config_simple.py


class TrafficLogModel:
    """
    Traffic Log Model - Stores all HTTP requests
    
    Table: traffic_logs
    Purpose: Log every incoming HTTP request with threat analysis
    """
    
    # Schema definition
    SCHEMA = {
        'table_name': 'traffic_logs',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'timestamp': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'ip_address': 'VARCHAR(45) NOT NULL',
            'method': 'VARCHAR(10) NOT NULL',
            'url': 'TEXT NOT NULL',
            'headers': 'JSONB',
            'body': 'TEXT',
            'query_params': 'JSONB',
            'threat_score': 'FLOAT DEFAULT 0.0',
            'is_blocked': 'BOOLEAN DEFAULT FALSE',
            'attack_type': 'VARCHAR(100)',
            'features': 'JSONB',
            'response_time': 'FLOAT'
        },
        'indexes': [
            'CREATE INDEX idx_traffic_logs_timestamp ON traffic_logs(timestamp DESC)',
            'CREATE INDEX idx_traffic_logs_ip ON traffic_logs(ip_address)',
            'CREATE INDEX idx_traffic_logs_blocked ON traffic_logs(is_blocked)'
        ]
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
        ip_address: str = '',
        method: str = '',
        url: str = '',
        headers: Optional[Dict] = None,
        body: str = '',
        query_params: Optional[Dict] = None,
        threat_score: float = 0.0,
        is_blocked: bool = False,
        attack_type: Optional[str] = None,
        features: Optional[List[float]] = None,
        response_time: float = 0.0
    ):
        self.id = id
        self.timestamp = timestamp or datetime.now()
        self.ip_address = ip_address
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.query_params = query_params or {}
        self.threat_score = threat_score
        self.is_blocked = is_blocked
        self.attack_type = attack_type
        self.features = features or []
        self.response_time = response_time
    
    def to_dict(self) -> Dict:
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'ip_address': self.ip_address,
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body,
            'query_params': self.query_params,
            'threat_score': self.threat_score,
            'is_blocked': self.is_blocked,
            'attack_type': self.attack_type,
            'features': self.features,
            'response_time': self.response_time
        }
    
    def __repr__(self):
        return f"<TrafficLog(id={self.id}, ip={self.ip_address}, blocked={self.is_blocked})>"


class AttackPatternModel:
    """
    Attack Pattern Model - Known attack signatures
    
    Table: attack_patterns
    Purpose: Store regex patterns and signatures for known attacks
    """
    
    SCHEMA = {
        'table_name': 'attack_patterns',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'pattern_name': 'VARCHAR(100) NOT NULL UNIQUE',
            'pattern_regex': 'TEXT NOT NULL',
            'severity': "VARCHAR(20) DEFAULT 'medium'",
            'description': 'TEXT',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
        }
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        pattern_name: str = '',
        pattern_regex: str = '',
        severity: str = 'medium',
        description: Optional[str] = None,
        created_at: Optional[datetime] = None
    ):
        self.id = id
        self.pattern_name = pattern_name
        self.pattern_regex = pattern_regex
        self.severity = severity
        self.description = description
        self.created_at = created_at or datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'pattern_name': self.pattern_name,
            'pattern_regex': self.pattern_regex,
            'severity': self.severity,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<AttackPattern(name={self.pattern_name}, severity={self.severity})>"


class WhitelistModel:
    """
    Whitelist Model - Trusted IP addresses
    
    Table: whitelist
    Purpose: Store IP addresses that should always be allowed
    """
    
    SCHEMA = {
        'table_name': 'whitelist',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'ip_address': 'VARCHAR(45) NOT NULL UNIQUE',
            'reason': 'TEXT',
            'added_by': 'VARCHAR(100)',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
        }
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        ip_address: str = '',
        reason: Optional[str] = None,
        added_by: str = 'admin',
        created_at: Optional[datetime] = None
    ):
        self.id = id
        self.ip_address = ip_address
        self.reason = reason
        self.added_by = added_by
        self.created_at = created_at or datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'added_by': self.added_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<Whitelist(ip={self.ip_address})>"


class BlacklistModel:
    """
    Blacklist Model - Blocked IP addresses
    
    Table: blacklist
    Purpose: Store IP addresses that should be blocked
    """
    
    SCHEMA = {
        'table_name': 'blacklist',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'ip_address': 'VARCHAR(45) NOT NULL UNIQUE',
            'reason': 'TEXT',
            'added_by': 'VARCHAR(100)',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'expires_at': 'TIMESTAMP'
        }
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        ip_address: str = '',
        reason: Optional[str] = None,
        added_by: str = 'admin',
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None
    ):
        self.id = id
        self.ip_address = ip_address
        self.reason = reason
        self.added_by = added_by
        self.created_at = created_at or datetime.now()
        self.expires_at = expires_at
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'added_by': self.added_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    def __repr__(self):
        return f"<Blacklist(ip={self.ip_address}, expires={self.expires_at})>"


class WAFConfigModel:
    """
    WAF Configuration Model - System settings
    
    Table: waf_config
    Purpose: Store configurable WAF settings
    """
    
    SCHEMA = {
        'table_name': 'waf_config',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'config_key': 'VARCHAR(100) NOT NULL UNIQUE',
            'config_value': 'TEXT NOT NULL',
            'updated_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
        }
    }
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'threat_threshold': '0.7',
        'enable_blocking': 'true',
        'enable_logging': 'true',
        'rate_limit_enabled': 'true',
        'rate_limit_requests': '100',
        'rate_limit_window': '60',
        'enable_anomaly_detection': 'true',
        'log_retention_days': '30'
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        config_key: str = '',
        config_value: str = '',
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.config_key = config_key
        self.config_value = config_value
        self.updated_at = updated_at or datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'config_key': self.config_key,
            'config_value': self.config_value,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f"<WAFConfig(key={self.config_key}, value={self.config_value})>"


class MLModelModel:
    """
    ML Model Metadata Model
    
    Table: ml_models
    Purpose: Store metadata about trained ML models (for Person 3)
    """
    
    SCHEMA = {
        'table_name': 'ml_models',
        'columns': {
            'id': 'SERIAL PRIMARY KEY',
            'model_name': 'VARCHAR(100) NOT NULL',
            'model_version': 'VARCHAR(20) NOT NULL',
            'accuracy': 'FLOAT',
            'file_path': 'TEXT',
            'description': 'TEXT',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'UNIQUE': '(model_name, model_version)'
        }
    }
    
    def __init__(
        self,
        id: Optional[int] = None,
        model_name: str = '',
        model_version: str = '',
        accuracy: Optional[float] = None,
        file_path: Optional[str] = None,
        description: Optional[str] = None,
        created_at: Optional[datetime] = None
    ):
        self.id = id
        self.model_name = model_name
        self.model_version = model_version
        self.accuracy = accuracy
        self.file_path = file_path
        self.description = description
        self.created_at = created_at or datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'model_name': self.model_name,
            'model_version': self.model_version,
            'accuracy': self.accuracy,
            'file_path': self.file_path,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<MLModel(name={self.model_name}, version={self.model_version}, accuracy={self.accuracy})>"


# Dictionary of all models for reference
ALL_MODELS = {
    'traffic_logs': TrafficLogModel,
    'attack_patterns': AttackPatternModel,
    'whitelist': WhitelistModel,
    'blacklist': BlacklistModel,
    'waf_config': WAFConfigModel,
    'ml_models': MLModelModel
}


def get_all_schemas() -> Dict[str, Dict]:
    """
    Get all table schemas for reference
    
    Returns:
        Dictionary mapping table names to their schema definitions
    """
    return {
        'traffic_logs': TrafficLogModel.SCHEMA,
        'attack_patterns': AttackPatternModel.SCHEMA,
        'whitelist': WhitelistModel.SCHEMA,
        'blacklist': BlacklistModel.SCHEMA,
        'waf_config': WAFConfigModel.SCHEMA,
        'ml_models': MLModelModel.SCHEMA
    }


def print_schema_documentation():
    """Print formatted documentation of all database schemas"""
    print("\n" + "="*60)
    print("📊 AI-WAF DATABASE SCHEMA DOCUMENTATION")
    print("="*60 + "\n")
    
    schemas = get_all_schemas()
    
    for table_name, schema in schemas.items():
        print(f"\n{'─'*60}")
        print(f"Table: {table_name}")
        print(f"{'─'*60}")
        
        print("\nColumns:")
        for col_name, col_type in schema['columns'].items():
            print(f"  • {col_name:20} {col_type}")
        
        if 'indexes' in schema:
            print("\nIndexes:")
            for idx in schema['indexes']:
                print(f"  • {idx}")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    """
    Run this file to see database schema documentation
    
    Usage: python database/models.py
    """
    print_schema_documentation()
    
    print("\n📝 MODEL EXAMPLES:\n")
    
    # Example 1: Traffic Log
    log = TrafficLogModel(
        ip_address='192.168.1.100',
        method='GET',
        url='/api/users',
        threat_score=0.15,
        is_blocked=False
    )
    print(f"Traffic Log: {log}")
    print(f"Dict: {log.to_dict()}\n")
    
    # Example 2: Whitelist
    whitelist = WhitelistModel(
        ip_address='192.168.1.1',
        reason='Office IP',
        added_by='admin'
    )
    print(f"Whitelist: {whitelist}")
    print(f"Dict: {whitelist.to_dict()}\n")
    
    # Example 3: ML Model
    ml_model = MLModelModel(
        model_name='random_forest_classifier',
        model_version='1.0',
        accuracy=0.95,
        file_path='data/trained_models/rf_model.pkl'
    )
    print(f"ML Model: {ml_model}")
    print(f"Dict: {ml_model.to_dict()}\n")
    
    print("="*60)
    print("✅ Model definitions loaded successfully!")
    print("💡 These models are for reference/documentation only")
    print("💡 Actual operations use db_operations.py with direct SQL")
    print("="*60 + "\n")