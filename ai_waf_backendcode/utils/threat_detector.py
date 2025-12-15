"""
Threat Detector Module
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Purpose: Combines ML prediction with rule-based detection

This module:
1. Manages whitelist/blacklist checking
2. Coordinates between feature extraction and ML prediction
3. Implements rule-based detection as fallback
4. Provides threat scoring and classification
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
import json


class ThreatDetector:
    """
    Advanced threat detection combining ML and rule-based approaches
    """
    
    def __init__(self, ml_predictor=None):
        """
        Initialize threat detector
        
        Args:
            ml_predictor: ML model predictor instance (from Person 3)
        """
        self.ml_predictor = ml_predictor
        
        # In-memory storage (will be replaced by database from Person 2)
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
        # TODO: Replace with Person 2's database function
        # from database.db_operations import check_whitelist
        # return check_whitelist(ip_address)
        
        return ip_address in self.whitelist
    
    def check_blacklist(self, ip_address):
        """
        Check if IP is in blacklist
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            bool: True if blacklisted
        """
        # TODO: Replace with Person 2's database function
        # from database.db_operations import check_blacklist
        # return check_blacklist(ip_address)
        
        return ip_address in self.blacklist
    
    def add_to_whitelist(self, ip_address):
        """Add IP to whitelist"""
        self.whitelist.add(ip_address)
        print(f"[INFO] Added {ip_address} to whitelist")
        return True
    
    def add_to_blacklist(self, ip_address):
        """Add IP to blacklist"""
        self.blacklist.add(ip_address)
        print(f"[INFO] Added {ip_address} to blacklist")
        return True
    
    def remove_from_whitelist(self, ip_address):
        """Remove IP from whitelist"""
        if ip_address in self.whitelist:
            self.whitelist.remove(ip_address)
            print(f"[INFO] Removed {ip_address} from whitelist")
            return True
        return False
    
    def remove_from_blacklist(self, ip_address):
        """Remove IP from blacklist"""
        if ip_address in self.blacklist:
            self.blacklist.remove(ip_address)
            print(f"[INFO] Removed {ip_address} from blacklist")
            return True
        return False
    
    def get_whitelist(self):
        """Get all whitelisted IPs"""
        return list(self.whitelist)
    
    def get_blacklist(self):
        """Get all blacklisted IPs"""
        return list(self.blacklist)
    
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
    
    def ml_based_detection(self, features):
        """
        ML-based threat detection
        
        Args:
            features (list): 20 extracted features
            
        Returns:
            dict: Detection results with threat score and type
        """
        if self.ml_predictor is None:
            # Fallback to simple heuristic if ML model not available
            # Check key indicators from features
            has_sql = features[6]  # has_sql_keywords
            sql_count = features[7]  # sql_keyword_count
            has_xss = features[8]  # has_xss_patterns
            has_path_trav = features[10]  # has_path_traversal
            has_cmd_inj = features[11]  # has_command_injection_chars
            
            if sql_count > 2:
                return {'threat_score': 0.95, 'attack_type': 'SQL Injection', 'method': 'heuristic'}
            elif has_xss:
                return {'threat_score': 0.90, 'attack_type': 'XSS', 'method': 'heuristic'}
            elif has_path_trav:
                return {'threat_score': 0.85, 'attack_type': 'Path Traversal', 'method': 'heuristic'}
            elif has_cmd_inj:
                return {'threat_score': 0.88, 'attack_type': 'Command Injection', 'method': 'heuristic'}
            else:
                return {'threat_score': 0.15, 'attack_type': 'Benign', 'method': 'heuristic'}
        
        try:
            # Call Person 3's ML model
            # TODO: Replace with actual ML predictor
            # threat_score, attack_type = self.ml_predictor.predict(features)
            
            # For now, using mock
            threat_score, attack_type = self._mock_ml_predict(features)
            
            return {
                'threat_score': threat_score,
                'attack_type': attack_type,
                'method': 'ml_model'
            }
        except Exception as e:
            print(f"[ERROR] ML prediction failed: {str(e)}")
            # Fallback to rule-based
            return {'threat_score': 0.0, 'attack_type': 'Unknown', 'method': 'error'}
    
    def _mock_ml_predict(self, features):
        """Mock ML prediction (temporary)"""
        # Simple heuristic based on features
        if features[7] > 2:  # sql_keyword_count
            return 0.95, "SQL Injection"
        elif features[8] > 0:  # xss_keyword_count
            return 0.90, "XSS"
        elif features[10] == 1:  # has_path_traversal
            return 0.85, "Path Traversal"
        elif features[11] == 1:  # has_command_injection
            return 0.88, "Command Injection"
        else:
            return 0.15, "Benign"
    
    def detect_threat(self, request_data, features):
        """
        Main threat detection combining ML and rules
        
        Args:
            request_data (dict): Request data
            features (list): 20 extracted features
            
        Returns:
            dict: Complete threat analysis
        """
        # Step 1: ML-based detection
        ml_result = self.ml_based_detection(features)
        
        # Step 2: Rule-based detection
        rule_result = self.rule_based_detection(request_data)
        
        # Step 3: Combine results (use highest threat score)
        final_score = max(ml_result['threat_score'], rule_result['threat_score'])
        
        # Determine final attack type
        if ml_result['threat_score'] >= rule_result['threat_score']:
            final_attack_type = ml_result['attack_type']
            detection_method = ml_result['method']
        else:
            final_attack_type = rule_result['attack_type']
            detection_method = 'rule_based'
        
        # Step 4: Check for additional indicators
        confidence = self._calculate_confidence(ml_result, rule_result)
        
        return {
            'threat_score': final_score,
            'attack_type': final_attack_type,
            'confidence': confidence,
            'detection_method': detection_method,
            'ml_score': ml_result['threat_score'],
            'rule_score': rule_result['threat_score'],
            'features': features
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
            'rate_limited_ips': len([ip for ip, reqs in self.request_counts.items() if len(reqs) > self.rate_limit_threshold]),
            'ml_model_loaded': self.ml_predictor is not None
        }


# Standalone testing
if __name__ == "__main__":
    """Test the threat detector"""
    print("="*60)
    print("THREAT DETECTOR TESTING")
    print("="*60)
    
    detector = ThreatDetector()
    
    # Test 1: Whitelist/Blacklist
    print("\n[TEST 1] Whitelist/Blacklist")
    detector.add_to_whitelist("192.168.1.100")
    detector.add_to_blacklist("10.0.0.666")
    print(f"Whitelist: {detector.get_whitelist()}")
    print(f"Blacklist: {detector.get_blacklist()}")
    print(f"Is 192.168.1.100 whitelisted? {detector.check_whitelist('192.168.1.100')}")
    print(f"Is 10.0.0.666 blacklisted? {detector.check_blacklist('10.0.0.666')}")
    
    # Test 2: Rule-based detection - SQL Injection
    print("\n[TEST 2] Rule-based Detection - SQL Injection")
    sql_request = {
        'url': "http://example.com/search?q=1' OR '1'='1",
        'query_string': "q=1' OR '1'='1",
        'body': ''
    }
    result = detector.rule_based_detection(sql_request)
    print(f"Threat Score: {result['threat_score']}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Detected Patterns: {result['detected_patterns']}")
    
    # Test 3: Rule-based detection - XSS
    print("\n[TEST 3] Rule-based Detection - XSS")
    xss_request = {
        'url': "http://example.com/comment",
        'query_string': "text=<script>alert('XSS')</script>",
        'body': ''
    }
    result = detector.rule_based_detection(xss_request)
    print(f"Threat Score: {result['threat_score']}")
    print(f"Attack Type: {result['attack_type']}")
    
    # Test 4: Rate limiting
    print("\n[TEST 4] Rate Limiting")
    test_ip = "192.168.1.200"
    for i in range(5):
        is_limited, count = detector.check_rate_limit(test_ip)
        print(f"Request {i+1}: Count={count}, Limited={is_limited}")
    
    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("="*60)