"""
Threat Detector Module
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Modified: Integrated with Person 3's ML Models
Purpose: Combines ML prediction with rule-based detection

This module:
1. Manages whitelist/blacklist checking
2. Coordinates between feature extraction and ML prediction
3. Implements rule-based detection as fallback
4. Provides threat scoring and classification
"""

import re
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ============================================================================
# PERSON 3's ML MODELS INTEGRATION
# ============================================================================
try:
    from models.ml_model import MLModel
    from models.anomaly_detector import AnomalyDetector
    
    # Initialize ML models
    print("🤖 [ThreatDetector] Initializing ML models...")
    _ml_classifier = MLModel()
    _anomaly_detector = AnomalyDetector()
    
    # Load models
    _ml_loaded = _ml_classifier.load_model()
    _anomaly_loaded = _anomaly_detector.load_model()
    
    if _ml_loaded and _anomaly_loaded:
        print("✅ [ThreatDetector] Random Forest & Isolation Forest loaded")
        ML_MODELS_AVAILABLE = True
    elif _ml_loaded:
        print("✅ [ThreatDetector] Random Forest loaded (Isolation Forest not available)")
        ML_MODELS_AVAILABLE = True
    else:
        print("⚠️  [ThreatDetector] ML models not loaded - using rule-based only")
        ML_MODELS_AVAILABLE = False
        
except Exception as e:
    print(f"⚠️  [ThreatDetector] ML models not available: {e}")
    ML_MODELS_AVAILABLE = False
    _ml_classifier = None
    _anomaly_detector = None

# ============================================================================
# PERSON 2's DATABASE OPERATIONS INTEGRATION
# ============================================================================
try:
    from database.db_operations import DatabaseOperations
    
    # Initialize database operations
    print("🗄️  [ThreatDetector] Initializing database operations...")
    _db_ops = DatabaseOperations()
    DB_AVAILABLE = True
    print("✅ [ThreatDetector] Database operations initialized")
    
except Exception as e:
    print(f"⚠️  [ThreatDetector] Database operations not available: {e}")
    DB_AVAILABLE = False
    _db_ops = None


class ThreatDetector:
    """
    Advanced threat detection combining ML and rule-based approaches
    Now powered by Person 3's trained models!
    """
    
    def __init__(self, ml_predictor=None):
        """
        Initialize threat detector
        
        Args:
            ml_predictor: ML model predictor instance (optional, uses global if None)
        """
        # Use provided ML predictor or global one
        if ml_predictor is not None:
            self.ml_classifier = ml_predictor
            self.anomaly_detector = None
            self.ml_available = True
        else:
            self.ml_classifier = _ml_classifier if ML_MODELS_AVAILABLE else None
            self.anomaly_detector = _anomaly_detector if ML_MODELS_AVAILABLE else None
            self.ml_available = ML_MODELS_AVAILABLE
        
        # Database operations instance
        self.db_ops = _db_ops if DB_AVAILABLE else None
        self.db_available = DB_AVAILABLE
        
        # Fallback in-memory storage (only used if database is not available)
        if not self.db_available:
            self.whitelist = set(['127.0.0.1', 'localhost', '::1'])
            self.blacklist = set()
        
        # Rate limiting storage
        self.request_counts = defaultdict(list)  # IP -> list of timestamps
        self.rate_limit_threshold = 100  # requests per minute
        
        # Known attack patterns (rule-based detection)
        self.attack_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
                r"(--|\#|\/\*|\*\/)",
                r"(\bexec\b|\bexecute\b).*\(",
                r"(\bdrop\b|\bdelete\b|\binsert\b|\bupdate\b).*\b(table|from|into)\b",
                r"(sleep\(|benchmark\(|waitfor\s+delay)",
                r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript\s*:",
                r"on(error|load|click|mouse\w+)\s*=",
                r"<iframe[^>]*>",
                r"<img[^>]*on\w+\s*=",
                r"document\.(cookie|write|location)",
                r"(alert|confirm|prompt)\s*\(",
                r"<svg[^>]*on\w+\s*=",
            ],
            'path_traversal': [
                r"\.\.[\/\\]",
                r"\.\.%2[fF]",
                r"\.\.%5[cC]",
                r"%2e%2e[\/\\]",
                r"(\/etc\/passwd|\/etc\/shadow)",
                r"(c:\\windows|c:\\winnt)",
            ],
            'command_injection': [
                r"[;&|`$]\s*(cat|ls|dir|type|echo|wget|curl)",
                r"\$\(.*\)",
                r"`.*`",
                r"(bash|sh|cmd|powershell)\s+",
                r"(\|\||&&)\s*\w+",
            ],
            'ldap_injection': [
                r"(\*\)|\(\||\(\&)",
                r"(cn=|ou=|dc=).*[\*\(\)]",
            ],
            'xml_injection': [
                r"<!ENTITY",
                r"<!DOCTYPE.*\[",
                r"<!\[CDATA\[",
            ]
        }
    
    def check_whitelist(self, ip_address):
        """
        Check if IP is in whitelist
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            bool: True if whitelisted
        """
        if self.db_available and self.db_ops:
            try:
                return self.db_ops.check_whitelist(ip_address)
            except Exception as e:
                print(f"[ERROR] Database whitelist check failed: {e}")
                # Fallback to in-memory if available
                if hasattr(self, 'whitelist'):
                    return ip_address in self.whitelist
        
        # Fallback: in-memory storage
        if hasattr(self, 'whitelist'):
            return ip_address in self.whitelist
        
        return False
    
    def check_blacklist(self, ip_address):
        """
        Check if IP is in blacklist
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            bool: True if blacklisted
        """
        if self.db_available and self.db_ops:
            try:
                return self.db_ops.check_blacklist(ip_address)
            except Exception as e:
                print(f"[ERROR] Database blacklist check failed: {e}")
                # Fallback to in-memory if available
                if hasattr(self, 'blacklist'):
                    return ip_address in self.blacklist
        
        # Fallback: in-memory storage
        if hasattr(self, 'blacklist'):
            return ip_address in self.blacklist
        
        return False
    
    def add_to_whitelist(self, ip_address):
        """Add IP to whitelist"""
        if self.db_available and self.db_ops:
            try:
                success = self.db_ops.add_to_whitelist(ip_address)
                if success:
                    print(f"[INFO] Added {ip_address} to database whitelist")
                return success
            except Exception as e:
                print(f"[ERROR] Database whitelist add failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'whitelist'):
                    self.whitelist.add(ip_address)
                    print(f"[INFO] Added {ip_address} to in-memory whitelist (fallback)")
                    return True
        
        # Fallback: in-memory storage
        if hasattr(self, 'whitelist'):
            self.whitelist.add(ip_address)
            print(f"[INFO] Added {ip_address} to in-memory whitelist")
            return True
        
        return False
    
    def add_to_blacklist(self, ip_address):
        """Add IP to blacklist"""
        if self.db_available and self.db_ops:
            try:
                success = self.db_ops.add_to_blacklist(ip_address)
                if success:
                    print(f"[INFO] Added {ip_address} to database blacklist")
                return success
            except Exception as e:
                print(f"[ERROR] Database blacklist add failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'blacklist'):
                    self.blacklist.add(ip_address)
                    print(f"[INFO] Added {ip_address} to in-memory blacklist (fallback)")
                    return True
        
        # Fallback: in-memory storage
        if hasattr(self, 'blacklist'):
            self.blacklist.add(ip_address)
            print(f"[INFO] Added {ip_address} to in-memory blacklist")
            return True
        
        return False
    
    def remove_from_whitelist(self, ip_address):
        """Remove IP from whitelist"""
        if self.db_available and self.db_ops:
            try:
                success = self.db_ops.remove_from_whitelist(ip_address)
                if success:
                    print(f"[INFO] Removed {ip_address} from database whitelist")
                return success
            except Exception as e:
                print(f"[ERROR] Database whitelist remove failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'whitelist') and ip_address in self.whitelist:
                    self.whitelist.remove(ip_address)
                    print(f"[INFO] Removed {ip_address} from in-memory whitelist (fallback)")
                    return True
        
        # Fallback: in-memory storage
        if hasattr(self, 'whitelist') and ip_address in self.whitelist:
            self.whitelist.remove(ip_address)
            print(f"[INFO] Removed {ip_address} from in-memory whitelist")
            return True
        
        return False
    
    def remove_from_blacklist(self, ip_address):
        """Remove IP from blacklist"""
        if self.db_available and self.db_ops:
            try:
                success = self.db_ops.remove_from_blacklist(ip_address)
                if success:
                    print(f"[INFO] Removed {ip_address} from database blacklist")
                return success
            except Exception as e:
                print(f"[ERROR] Database blacklist remove failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'blacklist') and ip_address in self.blacklist:
                    self.blacklist.remove(ip_address)
                    print(f"[INFO] Removed {ip_address} from in-memory blacklist (fallback)")
                    return True
        
        # Fallback: in-memory storage
        if hasattr(self, 'blacklist') and ip_address in self.blacklist:
            self.blacklist.remove(ip_address)
            print(f"[INFO] Removed {ip_address} from in-memory blacklist")
            return True
        
        return False
    
    def get_whitelist(self):
        """Get all whitelisted IPs"""
        if self.db_available and self.db_ops:
            try:
                return self.db_ops.get_whitelist()
            except Exception as e:
                print(f"[ERROR] Database get whitelist failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'whitelist'):
                    return list(self.whitelist)
        
        # Fallback: in-memory storage
        if hasattr(self, 'whitelist'):
            return list(self.whitelist)
        
        return []
    
    def get_blacklist(self):
        """Get all blacklisted IPs"""
        if self.db_available and self.db_ops:
            try:
                return self.db_ops.get_blacklist()
            except Exception as e:
                print(f"[ERROR] Database get blacklist failed: {e}")
                # Fallback to in-memory
                if hasattr(self, 'blacklist'):
                    return list(self.blacklist)
        
        # Fallback: in-memory storage
        if hasattr(self, 'blacklist'):
            return list(self.blacklist)
        
        return []
    
    def check_rate_limit(self, ip_address):
        """
        Check if IP has exceeded rate limit
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            tuple: (is_limited, request_count)
        """
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        # Get requests from this IP in last minute
        recent_requests = [
            ts for ts in self.request_counts[ip_address]
            if ts > one_minute_ago
        ]
        
        # Update the list
        self.request_counts[ip_address] = recent_requests
        self.request_counts[ip_address].append(now)
        
        # Check if exceeded threshold
        count = len(recent_requests)
        is_limited = count > self.rate_limit_threshold
        
        if is_limited:
            print(f"[WARNING] Rate limit exceeded for {ip_address}: {count} requests/min")
        
        return is_limited, count
    
    def rule_based_detection(self, request_data):
        """
        Rule-based threat detection using regex patterns
        
        Args:
            request_data (dict): Request data
            
        Returns:
            dict: Detection results with threat score and type
        """
        # Combine all text to analyze
        url = request_data.get('url', '')
        query_string = request_data.get('query_string', '')
        body = request_data.get('body', '')
        full_text = f"{url} {query_string} {body}".lower()
        
        detected_attacks = []
        max_score = 0.0
        
        # Check each attack type
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, full_text, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    # Assign scores based on attack type
                    if attack_type == 'sql_injection':
                        max_score = max(max_score, 0.95)
                    elif attack_type == 'xss':
                        max_score = max(max_score, 0.90)
                    elif attack_type == 'command_injection':
                        max_score = max(max_score, 0.92)
                    elif attack_type == 'path_traversal':
                        max_score = max(max_score, 0.85)
                    else:
                        max_score = max(max_score, 0.80)
                    break
        
        # Determine primary attack type
        if detected_attacks:
            attack_type = detected_attacks[0].replace('_', ' ').title()
        else:
            attack_type = 'Benign'
            max_score = 0.1
        
        return {
            'threat_score': max_score,
            'attack_type': attack_type,
            'detected_patterns': detected_attacks,
            'method': 'rule_based'
        }
    
    def ml_based_detection(self, request_data):
        """
        ML-based threat detection using Person 3's trained models
        
        Args:
            request_data (dict): Request data dictionary
            
        Returns:
            dict: Detection results with threat score and type
        """
        if not self.ml_available or self.ml_classifier is None:
            # Fallback to rule-based if ML not available
            print("[INFO] ML models not available, using rule-based detection")
            return self.rule_based_detection(request_data)
        
        try:
            # Get Random Forest prediction
            rf_result = self.ml_classifier.predict(request_data)
            
            # Get Anomaly Detection prediction (if available)
            if self.anomaly_detector and _anomaly_loaded:
                anomaly_result = self.anomaly_detector.predict_anomaly(request_data)
                
                # Combine predictions
                # Take the higher threat level
                rf_score = rf_result['attack_probability']
                anomaly_score = abs(anomaly_result.get('anomaly_score', 0.0))
                
                # Normalize anomaly score to 0-1 range
                anomaly_score_normalized = min(anomaly_score, 1.0)
                
                # Use maximum threat score
                threat_score = max(rf_score, anomaly_score_normalized)
                
                # Determine attack type
                if rf_result['is_attack']:
                    attack_type = rf_result['prediction']
                elif anomaly_result['is_anomaly']:
                    attack_type = f"Anomaly ({anomaly_result['severity']})"
                else:
                    attack_type = "Benign"
                
                return {
                    'threat_score': float(threat_score),
                    'attack_type': attack_type,
                    'method': 'ml_combined',
                    'rf_confidence': rf_result['confidence'],
                    'anomaly_detected': anomaly_result['is_anomaly']
                }
            else:
                # Only Random Forest available
                return {
                    'threat_score': float(rf_result['attack_probability']),
                    'attack_type': rf_result['prediction'],
                    'method': 'ml_random_forest',
                    'rf_confidence': rf_result['confidence']
                }
                
        except Exception as e:
            print(f"[ERROR] ML prediction failed: {str(e)}")
            import traceback
            traceback.print_exc()
            # Fallback to rule-based
            return self.rule_based_detection(request_data)
    
    def detect_threat(self, request_data, features=None):
        """
        Main threat detection combining ML and rules
        
        Args:
            request_data (dict): Request data
            features (list): 20 extracted features (optional, will extract if not provided)
            
        Returns:
            dict: Complete threat analysis
        """
        # Step 1: ML-based detection (uses request_data directly)
        ml_result = self.ml_based_detection(request_data)
        
        # Step 2: Rule-based detection (backup/validation)
        rule_result = self.rule_based_detection(request_data)
        
        # Step 3: Combine results (use highest threat score)
        final_score = max(ml_result['threat_score'], rule_result['threat_score'])
        
        # Determine final attack type (prioritize ML if available)
        if self.ml_available and ml_result['threat_score'] >= rule_result['threat_score']:
            final_attack_type = ml_result['attack_type']
            detection_method = ml_result['method']
        else:
            final_attack_type = rule_result['attack_type']
            detection_method = 'rule_based'
        
        # Step 4: Calculate confidence
        confidence = self._calculate_confidence(ml_result, rule_result)
        
        # Step 5: Get threat level
        threat_level = self.get_threat_level(final_score)
        
        return {
            'threat_score': final_score,
            'attack_type': final_attack_type,
            'threat_level': threat_level,
            'confidence': confidence,
            'detection_method': detection_method,
            'ml_score': ml_result['threat_score'],
            'rule_score': rule_result['threat_score'],
            'ml_powered': self.ml_available,
            'details': {
                'ml_result': ml_result,
                'rule_result': rule_result
            }
        }
    
    def _calculate_confidence(self, ml_result, rule_result):
        """
        Calculate confidence level based on agreement between methods
        
        Args:
            ml_result (dict): ML detection result
            rule_result (dict): Rule-based detection result
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        # If both methods agree on threat
        ml_malicious = ml_result['threat_score'] > 0.7
        rule_malicious = rule_result['threat_score'] > 0.7
        
        if ml_malicious and rule_malicious:
            # Both detected threat - high confidence
            return 0.95
        elif ml_malicious or rule_malicious:
            # Only one detected threat - medium confidence
            return 0.75
        else:
            # Neither detected threat - high confidence it's benign
            return 0.90
    
    def get_threat_level(self, threat_score):
        """
        Convert threat score to human-readable level
        
        Args:
            threat_score (float): Threat score (0.0 to 1.0)
            
        Returns:
            str: Threat level
        """
        if threat_score >= 0.9:
            return "CRITICAL"
        elif threat_score >= 0.7:
            return "HIGH"
        elif threat_score >= 0.5:
            return "MEDIUM"
        elif threat_score >= 0.3:
            return "LOW"
        else:
            return "SAFE"
    
    def get_statistics(self):
        """
        Get detector statistics
        
        Returns:
            dict: Statistics about detections
        """
        return {
            'whitelist_count': len(self.whitelist),
            'blacklist_count': len(self.blacklist),
            'rate_limited_ips': len([ip for ip, reqs in self.request_counts.items() 
                                    if len(reqs) > self.rate_limit_threshold]),
            'ml_models_available': self.ml_available,
            'random_forest_loaded': self.ml_classifier is not None,
            'isolation_forest_loaded': self.anomaly_detector is not None
        }


# Standalone testing
if __name__ == "__main__":
    """Test the threat detector"""
    print("="*70)
    print("THREAT DETECTOR TESTING (WITH ML INTEGRATION)")
    print("="*70)
    
    detector = ThreatDetector()
    
    # Test 1: Whitelist/Blacklist
    print("\n[TEST 1] Whitelist/Blacklist")
    detector.add_to_whitelist("192.168.1.100")
    detector.add_to_blacklist("10.0.0.666")
    print(f"Whitelist: {detector.get_whitelist()}")
    print(f"Blacklist: {detector.get_blacklist()}")
    print(f"Is 192.168.1.100 whitelisted? {detector.check_whitelist('192.168.1.100')}")
    print(f"Is 10.0.0.666 blacklisted? {detector.check_blacklist('10.0.0.666')}")
    
    # Test 2: Normal request
    print("\n[TEST 2] Normal Request (ML Detection)")
    normal_request = {
        'url': "http://localhost:8080/products?category=electronics",
        'path': '/products',
        'query_string': "category=electronics",
        'body': '',
        'method': 'GET'
    }
    result = detector.detect_threat(normal_request)
    print(f"Threat Score: {result['threat_score']:.2f}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Detection Method: {result['detection_method']}")
    print(f"ML Powered: {result['ml_powered']}")
    
    # Test 3: SQL Injection
    print("\n[TEST 3] SQL Injection Attack (ML + Rule Detection)")
    sql_request = {
        'url': "http://localhost:8080/search?q=1' OR '1'='1 UNION SELECT * FROM users--",
        'path': '/search',
        'query_string': "q=1' OR '1'='1 UNION SELECT * FROM users--",
        'body': '',
        'method': 'GET'
    }
    result = detector.detect_threat(sql_request)
    print(f"Threat Score: {result['threat_score']:.2f}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"ML Score: {result['ml_score']:.2f}")
    print(f"Rule Score: {result['rule_score']:.2f}")
    
    # Test 4: XSS Attack
    print("\n[TEST 4] XSS Attack (ML + Rule Detection)")
    xss_request = {
        'url': "http://localhost:8080/comment?text=<script>alert(document.cookie)</script>",
        'path': '/comment',
        'query_string': "text=<script>alert(document.cookie)</script>",
        'body': '',
        'method': 'POST'
    }
    result = detector.detect_threat(xss_request)
    print(f"Threat Score: {result['threat_score']:.2f}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Threat Level: {result['threat_level']}")
    
    # Test 5: Statistics
    print("\n[TEST 5] Detector Statistics")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*70)
    print("TESTING COMPLETE")
    print("="*70)