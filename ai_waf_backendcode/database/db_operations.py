"""
Database Operations for AI-WAF
Person 2: Database Manager
All CRUD operations for WAF system
Python 3.14 Compatible
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from database.db_config import get_db_cursor

logger = logging.getLogger(__name__)


class DatabaseOperations:
    """Handles all database CRUD operations for the WAF system"""
    
    # ==========================================
    # TRAFFIC LOGS OPERATIONS
    # ==========================================
    
    @staticmethod
    def log_request(request_data: Dict[str, Any]) -> Optional[int]:
        """
        Log an HTTP request to the database.
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            log_id (int) if successful, None if failed
            
        Usage (Person 1 will call this):
            db_ops = DatabaseOperations()
            log_id = db_ops.log_request({
                'ip_address': '192.168.1.1',
                'method': 'GET',
                'url': '/search?q=test',
                'headers': {'User-Agent': '...'},
                'body': '',
                'query_params': {'q': 'test'},
                'threat_score': 0.85,
                'is_blocked': True,
                'attack_type': 'SQL Injection',
                'features': [150, 45, 3, ...],
                'response_time': 0.025
            })
        """
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO traffic_logs (
                        ip_address, method, url, headers, body, 
                        query_params, threat_score, is_blocked, 
                        attack_type, features, response_time
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    request_data.get('ip_address'),
                    request_data.get('method'),
                    request_data.get('url'),
                    json.dumps(request_data.get('headers', {})),
                    request_data.get('body', ''),
                    json.dumps(request_data.get('query_params', {})),
                    request_data.get('threat_score', 0.0),
                    request_data.get('is_blocked', False),
                    request_data.get('attack_type'),
                    json.dumps(request_data.get('features', [])),
                    request_data.get('response_time', 0.0)
                ))
                
                log_id = cur.lastrowid
                logger.info(f"✅ Request logged with ID: {log_id}")
                return log_id
                
        except Exception as e:
            logger.error(f"❌ Failed to log request: {e}")
            return None
    
    
    @staticmethod
    def get_recent_logs(limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        Get recent traffic logs.
        
        Args:
            limit: Number of logs to retrieve
            offset: Number of logs to skip
            
        Returns:
            List of log dictionaries
        """
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT 
                        id, timestamp, ip_address, method, url,
                        threat_score, is_blocked, attack_type, response_time
                    FROM traffic_logs
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
                
                logs = cur.fetchall()
                return [dict(log) for log in logs]
                
        except Exception as e:
            logger.error(f"❌ Failed to get recent logs: {e}")
            return []
    
    
    @staticmethod
    def get_attack_logs(limit: int = 100) -> List[Dict]:
        """
        Get only blocked/attack traffic logs.
        
        Args:
            limit: Number of logs to retrieve
            
        Returns:
            List of attack log dictionaries
        """
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT 
                        id, timestamp, ip_address, method, url,
                        threat_score, attack_type, response_time
                    FROM traffic_logs
                    WHERE is_blocked = 1
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                
                logs = cur.fetchall()
                return [dict(log) for log in logs]
                
        except Exception as e:
            logger.error(f"❌ Failed to get attack logs: {e}")
            return []
    
    
    @staticmethod
    def get_log_by_id(log_id: int) -> Optional[Dict]:
        """Get a specific log by ID with full details"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT * FROM traffic_logs WHERE id = ?
                """, (log_id,))
                
                log = cur.fetchone()
                return dict(log) if log else None
                
        except Exception as e:
            logger.error(f"❌ Failed to get log by ID: {e}")
            return None
    
    
    @staticmethod
    def get_statistics() -> Dict[str, Any]:
        """
        Get dashboard statistics.
        
        Returns:
            Dictionary with various statistics
        """
        try:
            stats = {}
            
            with get_db_cursor() as cur:
                # Total requests
                cur.execute("SELECT COUNT(*) as total FROM traffic_logs")
                stats['total_requests'] = cur.fetchone()['total']
                
                # Blocked requests
                cur.execute("""
                    SELECT COUNT(*) as blocked 
                    FROM traffic_logs 
                    WHERE is_blocked = 1
                """)
                stats['blocked_requests'] = cur.fetchone()['blocked']
                
                # Requests in last 24 hours
                cur.execute("""
                    SELECT COUNT(*) as recent 
                    FROM traffic_logs 
                    WHERE timestamp > datetime('now', '-24 hours')
                """)
                stats['requests_24h'] = cur.fetchone()['recent']
                
                # Attacks in last 24 hours
                cur.execute("""
                    SELECT COUNT(*) as attacks 
                    FROM traffic_logs 
                    WHERE is_blocked = 1 
                    AND timestamp > datetime('now', '-24 hours')
                """)
                stats['attacks_24h'] = cur.fetchone()['attacks']
                
                # Attack types distribution
                cur.execute("""
                    SELECT attack_type, COUNT(*) as count
                    FROM traffic_logs
                    WHERE is_blocked = 1 AND attack_type IS NOT NULL
                    GROUP BY attack_type
                    ORDER BY count DESC
                    LIMIT 10
                """)
                stats['attack_types'] = [dict(row) for row in cur.fetchall()]
                
                # Top attacking IPs
                cur.execute("""
                    SELECT ip_address, COUNT(*) as count
                    FROM traffic_logs
                    WHERE is_blocked = 1
                    GROUP BY ip_address
                    ORDER BY count DESC
                    LIMIT 10
                """)
                stats['top_attackers'] = [dict(row) for row in cur.fetchall()]
                
                # Average threat score
                cur.execute("""
                    SELECT AVG(threat_score) as avg_score
                    FROM traffic_logs
                    WHERE threat_score > 0
                """)
                result = cur.fetchone()
                stats['avg_threat_score'] = float(result['avg_score']) if result['avg_score'] else 0.0
                
            logger.info("✅ Statistics retrieved successfully")
            return stats
            
        except Exception as e:
            logger.error(f"❌ Failed to get statistics: {e}")
            return {}
    
    
    # ==========================================
    # WHITELIST OPERATIONS
    # ==========================================
    
    @staticmethod
    def check_whitelist(ip_address: str) -> bool:
        """
        Check if an IP address is whitelisted.
        Person 1 will call this.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) as count 
                    FROM whitelist 
                    WHERE ip_address = ?
                """, (ip_address,))
                
                result = cur.fetchone()
                return result['count'] > 0
                
        except Exception as e:
            logger.error(f"❌ Failed to check whitelist: {e}")
            return False
    
    
    @staticmethod
    def add_to_whitelist(ip_address: str, reason: str = None, added_by: str = "admin") -> bool:
        """Add an IP address to whitelist"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT OR IGNORE INTO whitelist (ip_address, reason, added_by)
                    VALUES (?, ?, ?)
                """, (ip_address, reason, added_by))
                
                logger.info(f"✅ IP {ip_address} added to whitelist")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to add to whitelist: {e}")
            return False
    
    
    @staticmethod
    def remove_from_whitelist(ip_address: str) -> bool:
        """Remove an IP address from whitelist"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    DELETE FROM whitelist WHERE ip_address = ?
                """, (ip_address,))
                
                logger.info(f"✅ IP {ip_address} removed from whitelist")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to remove from whitelist: {e}")
            return False
    
    
    @staticmethod
    def get_whitelist() -> List[Dict]:
        """Get all whitelisted IP addresses"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT * FROM whitelist ORDER BY created_at DESC
                """)
                
                return [dict(row) for row in cur.fetchall()]
                
        except Exception as e:
            logger.error(f"❌ Failed to get whitelist: {e}")
            return []
    
    
    # ==========================================
    # BLACKLIST OPERATIONS
    # ==========================================
    
    @staticmethod
    def check_blacklist(ip_address: str) -> bool:
        """
        Check if an IP address is blacklisted.
        Person 1 will call this.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if blacklisted, False otherwise
        """
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) as count 
                    FROM blacklist 
                    WHERE ip_address = ? 
                    AND (expires_at IS NULL OR expires_at > datetime('now'))
                """, (ip_address,))
                
                result = cur.fetchone()
                return result['count'] > 0
                
        except Exception as e:
            logger.error(f"❌ Failed to check blacklist: {e}")
            return False
    
    
    @staticmethod
    def add_to_blacklist(
        ip_address: str, 
        reason: str = None, 
        added_by: str = "admin",
        expires_hours: int = None
    ) -> bool:
        """
        Add an IP address to blacklist.
        
        Args:
            ip_address: IP to blacklist
            reason: Reason for blacklisting
            added_by: Who added it
            expires_hours: Hours until expiration (None = permanent)
        """
        try:
            expires_at = None
            if expires_hours:
                expires_at = datetime.now() + timedelta(hours=expires_hours)
            
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT OR REPLACE INTO blacklist (ip_address, reason, added_by, expires_at, created_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                """, (ip_address, reason, added_by, expires_at))
                
                logger.info(f"✅ IP {ip_address} added to blacklist")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to add to blacklist: {e}")
            return False
    
    
    @staticmethod
    def remove_from_blacklist(ip_address: str) -> bool:
        """Remove an IP address from blacklist"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    DELETE FROM blacklist WHERE ip_address = %s
                """, (ip_address,))
                
                logger.info(f"✅ IP {ip_address} removed from blacklist")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to remove from blacklist: {e}")
            return False
    
    
    @staticmethod
    def get_blacklist() -> List[Dict]:
        """Get all blacklisted IP addresses"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT * FROM blacklist 
                    WHERE expires_at IS NULL OR expires_at > datetime('now')
                    ORDER BY created_at DESC
                """)
                
                return [dict(row) for row in cur.fetchall()]
                
        except Exception as e:
            logger.error(f"❌ Failed to get blacklist: {e}")
            return []
    
    
    # ==========================================
    # CONFIGURATION OPERATIONS
    # ==========================================
    
    @staticmethod
    def get_config(config_key: str) -> Optional[str]:
        """Get a configuration value"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT config_value FROM waf_config WHERE config_key = %s
                """, (config_key,))
                
                result = cur.fetchone()
                return result['config_value'] if result else None
                
        except Exception as e:
            logger.error(f"❌ Failed to get config: {e}")
            return None
    
    
    @staticmethod
    def get_all_config() -> Dict[str, str]:
        """Get all configuration values"""
        try:
            with get_db_cursor() as cur:
                cur.execute("SELECT config_key, config_value FROM waf_config")
                
                configs = {}
                for row in cur.fetchall():
                    configs[row['config_key']] = row['config_value']
                
                return configs
                
        except Exception as e:
            logger.error(f"❌ Failed to get all config: {e}")
            return {}
    
    
    @staticmethod
    def update_config(config_key: str, config_value: str) -> bool:
        """Update a configuration value"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT OR REPLACE INTO waf_config (config_key, config_value, updated_at)
                    VALUES (?, ?, datetime('now'))
                """, (config_key, config_value))
                
                logger.info(f"✅ Config updated: {config_key} = {config_value}")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to update config: {e}")
            return False
    
    
    # ==========================================
    # ML MODEL METADATA OPERATIONS
    # ==========================================
    
    @staticmethod
    def save_model_metadata(
        model_name: str,
        model_version: str,
        accuracy: float = None,
        file_path: str = None,
        description: str = None
    ) -> bool:
        """Save ML model metadata (Person 3 will use this)"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT OR REPLACE INTO ml_models (
                        model_name, model_version, accuracy, file_path, description, created_at
                    ) VALUES (?, ?, ?, ?, ?, datetime('now'))
                """, (model_name, model_version, accuracy, file_path, description))
                
                logger.info(f"✅ Model metadata saved: {model_name} v{model_version}")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to save model metadata: {e}")
            return False
    
    
    @staticmethod
    def get_latest_model(model_name: str) -> Optional[Dict]:
        """Get the latest version of a model"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT * FROM ml_models 
                    WHERE model_name = %s 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """, (model_name,))
                
                result = cur.fetchone()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Failed to get latest model: {e}")
            return None
    
    
    @staticmethod
    def get_all_models() -> List[Dict]:
        """Get all ML models"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT * FROM ml_models ORDER BY created_at DESC
                """)
                
                return [dict(row) for row in cur.fetchall()]
                
        except Exception as e:
            logger.error(f" Failed to get all models: {e}")
            return []


# Test the database operations
if __name__ == "__main__":
    print("\n" + "="*50)
    print("🧪 Testing Database Operations")
    print("="*50 + "\n")
    
    db_ops = DatabaseOperations()
    
    # Test 1: Log a request
    print("Test 1: Logging a test request...")
    log_id = db_ops.log_request({
        'ip_address': '192.168.1.100',
        'method': 'GET',
        'url': '/test',
        'headers': {'User-Agent': 'Test'},
        'body': '',
        'query_params': {},
        'threat_score': 0.3,
        'is_blocked': False,
        'attack_type': None,
        'features': [100, 50, 2, 10, 3.5, 0, 0, 0, 0, 0, 0, 0, 3, 5, 1, 8, 0.2, 0.6, 0, 15],
        'response_time': 0.015
    })
    print(f"Log ID: {log_id}\n")
    
    # Test 2: Get statistics
    print("Test 2: Getting statistics...")
    stats = db_ops.get_statistics()
    print(f"Total Requests: {stats.get('total_requests', 0)}")
    print(f"Blocked Requests: {stats.get('blocked_requests', 0)}\n")
    
    # Test 3: Whitelist operations
    print("Test 3: Whitelist operations...")
    db_ops.add_to_whitelist('192.168.1.1', 'Test IP')
    is_whitelisted = db_ops.check_whitelist('192.168.1.1')
    print(f"✅ IP 192.168.1.1 whitelisted: {is_whitelisted}\n")
    
    # Test 4: Blacklist operations
    print("Test 4: Blacklist operations...")
    db_ops.add_to_blacklist('10.0.0.1', 'Suspicious activity', expires_hours=24)
    is_blacklisted = db_ops.check_blacklist('10.0.0.1')
    print(f"IP 10.0.0.1 blacklisted: {is_blacklisted}\n")
    
    # Test 5: Configuration
    print("Test 5: Configuration operations...")
    config = db_ops.get_all_config()
    print(f"Loaded {len(config)} configuration values\n")
    
    print("="*50)
    print("All tests passed!")
    print("="*50)