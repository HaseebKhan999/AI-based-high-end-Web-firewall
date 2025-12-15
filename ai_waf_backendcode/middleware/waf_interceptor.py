"""
WAF Interceptor Middleware
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Purpose: Intercepts all incoming HTTP requests and applies WAF protection

This middleware:
1. Captures every HTTP request before it reaches the application
2. Extracts features from the request
3. Calls ML model for threat prediction
4. Blocks malicious requests or allows benign ones
5. Logs everything to database
"""

from flask import request, jsonify, g
from functools import wraps
import time
from datetime import datetime
import traceback

# Import feature extraction
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.feature_extraction import FeatureExtractor

# Mock functions (Replace these when Person 2 and 3 are ready)
def mock_ml_predict(features):
    """
    MOCK FUNCTION - Replace with Person 3's ML model
    
    Expected from Person 3:
    from ml.predict import MLPredictor
    predictor = MLPredictor()
    threat_score, attack_type = predictor.predict(features)
    """
    # Simple rule-based mock for testing
    if features[6] > 2:  # sql_keyword_count > 2
        return 0.95, "SQL Injection"
    elif features[8] > 0:  # xss_keyword_count > 0
        return 0.90, "XSS"
    elif features[10] == 1:  # has_path_traversal
        return 0.85, "Path Traversal"
    elif features[11] == 1:  # has_command_injection
        return 0.88, "Command Injection"
    else:
        return 0.15, "Benign"


def mock_db_log(log_data):
    """
    MOCK FUNCTION - Replace with Person 2's database logging
    
    Expected from Person 2:
    from database.db_operations import log_traffic
    log_id = log_traffic(log_data)
    """
    print(f"\n[MOCK DB LOG] Request logged at {log_data['timestamp']}")
    print(f"  IP: {log_data['ip_address']}")
    print(f"  Method: {log_data['method']} {log_data['url']}")
    print(f"  Threat Score: {log_data['threat_score']}")
    print(f"  Attack Type: {log_data['attack_type']}")
    print(f"  Status: {'BLOCKED' if log_data['is_blocked'] else 'ALLOWED'}")
    return 1  # Mock log ID


def mock_check_whitelist(ip_address):
    """
    MOCK FUNCTION - Replace with Person 2's whitelist check
    
    Expected from Person 2:
    from database.db_operations import check_whitelist
    is_whitelisted = check_whitelist(ip_address)
    """
    # Mock: localhost is always whitelisted
    whitelist = ['127.0.0.1', 'localhost']
    return ip_address in whitelist


def mock_check_blacklist(ip_address):
    """
    MOCK FUNCTION - Replace with Person 2's blacklist check
    
    Expected from Person 2:
    from database.db_operations import check_blacklist
    is_blacklisted = check_blacklist(ip_address)
    """
    # Mock: Some known malicious IPs
    blacklist = ['10.0.0.666', '192.168.1.666']
    return ip_address in blacklist


class WAFInterceptor:
    """
    Main WAF Interceptor Class
    Handles all request interception and threat detection logic
    """
    
    def __init__(self, threshold=0.7):
        """
        Initialize WAF Interceptor
        
        Args:
            threshold (float): Threat score threshold for blocking (default: 0.7)
        """
        self.threshold = threshold
        self.feature_extractor = FeatureExtractor()
        self.blocked_count = 0
        self.allowed_count = 0
        
    def extract_request_data(self, req):
        """
        Extract all relevant data from Flask request object
        
        Args:
            req: Flask request object
            
        Returns:
            dict: Extracted request data
        """
        # Get client IP address (handles proxy scenarios)
        if req.headers.get('X-Forwarded-For'):
            ip_address = req.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = req.remote_addr or '0.0.0.0'
        
        # Extract request data
        request_data = {
            'ip_address': ip_address,
            'method': req.method,
            'url': req.url,
            'path': req.path,
            'query_string': req.query_string.decode('utf-8', errors='ignore'),
            'headers': dict(req.headers),
            'body': req.get_data(as_text=True),
            'content_type': req.content_type or '',
            'user_agent': req.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        return request_data
    
    def check_whitelist_blacklist(self, ip_address):
        """
        Check if IP is in whitelist or blacklist
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            tuple: (should_block, reason)
        """
        # Check whitelist first (highest priority)
        if mock_check_whitelist(ip_address):
            return False, "Whitelisted IP"
        
        # Check blacklist
        if mock_check_blacklist(ip_address):
            return True, "Blacklisted IP"
        
        return None, None
    
    def analyze_request(self, request_data):
        """
        Main analysis function: Extract features and get ML prediction
        
        Args:
            request_data (dict): Extracted request data
            
        Returns:
            dict: Analysis results with threat score and attack type
        """
        try:
            # Step 1: Extract 20 features
            features = self.feature_extractor.extract_features(request_data)
            
            # Step 2: Get ML prediction
            # TODO: Replace with Person 3's actual ML model
            threat_score, attack_type = mock_ml_predict(features)
            
            # Step 3: Prepare analysis result
            analysis_result = {
                'features': features,
                'threat_score': threat_score,
                'attack_type': attack_type,
                'is_malicious': threat_score > self.threshold
            }
            
            return analysis_result
            
        except Exception as e:
            print(f"[ERROR] Analysis failed: {str(e)}")
            traceback.print_exc()
            # Default to safe mode: allow but log error
            return {
                'features': [0] * 20,
                'threat_score': 0.0,
                'attack_type': 'Analysis Error',
                'is_malicious': False,
                'error': str(e)
            }
    
    def log_request(self, request_data, analysis_result, is_blocked, response_time):
        """
        Log request to database
        
        Args:
            request_data (dict): Original request data
            analysis_result (dict): Analysis results
            is_blocked (bool): Whether request was blocked
            response_time (float): Processing time in seconds
        """
        try:
            log_data = {
                'timestamp': request_data['timestamp'],
                'ip_address': request_data['ip_address'],
                'method': request_data['method'],
                'url': request_data['url'],
                'path': request_data['path'],
                'query_string': request_data['query_string'],
                'user_agent': request_data['user_agent'],
                'threat_score': analysis_result['threat_score'],
                'attack_type': analysis_result['attack_type'],
                'is_blocked': is_blocked,
                'features': analysis_result['features'],
                'response_time': response_time
            }
            
            # TODO: Replace with Person 2's actual database logging
            log_id = mock_db_log(log_data)
            
            return log_id
            
        except Exception as e:
            print(f"[ERROR] Logging failed: {str(e)}")
            traceback.print_exc()
            return None
    
    def intercept(self, req):
        """
        Main interception logic - called for every request
        
        Args:
            req: Flask request object
            
        Returns:
            Response object if blocked, None if allowed
        """
        start_time = time.time()
        
        try:
            # Step 1: Extract request data
            request_data = self.extract_request_data(req)
            
            # Step 2: Check whitelist/blacklist
            should_block, reason = self.check_whitelist_blacklist(request_data['ip_address'])
            
            if should_block is not None:
                # IP is whitelisted or blacklisted
                response_time = time.time() - start_time
                
                if should_block:
                    self.blocked_count += 1
                    print(f"\n[BLOCKED] {reason}: {request_data['ip_address']}")
                    
                    # Log to database
                    self.log_request(
                        request_data,
                        {'threat_score': 1.0, 'attack_type': reason, 'features': [0]*20},
                        True,
                        response_time
                    )
                    
                    return jsonify({
                        'error': 'Access Denied',
                        'message': 'Your IP address has been blacklisted',
                        'blocked': True,
                        'reason': reason
                    }), 403
                else:
                    # Whitelisted - allow without analysis
                    self.allowed_count += 1
                    return None
            
            # Step 3: Analyze request with ML model
            analysis_result = self.analyze_request(request_data)
            
            # Step 4: Make decision
            is_blocked = analysis_result['is_malicious']
            response_time = time.time() - start_time
            
            # Step 5: Log request
            self.log_request(request_data, analysis_result, is_blocked, response_time)
            
            # Step 6: Block or allow
            if is_blocked:
                self.blocked_count += 1
                print(f"\n[BLOCKED] {analysis_result['attack_type']} detected")
                print(f"  URL: {request_data['url']}")
                print(f"  Threat Score: {analysis_result['threat_score']:.2f}")
                
                return jsonify({
                    'error': 'Request Blocked',
                    'message': f'Potential {analysis_result["attack_type"]} detected',
                    'blocked': True,
                    'threat_score': analysis_result['threat_score'],
                    'attack_type': analysis_result['attack_type']
                }), 403
            else:
                self.allowed_count += 1
                print(f"\n[ALLOWED] {request_data['method']} {request_data['path']} - Score: {analysis_result['threat_score']:.2f}")
                return None  # Allow request to proceed
                
        except Exception as e:
            print(f"[ERROR] WAF Interceptor failed: {str(e)}")
            traceback.print_exc()
            # Fail open: allow request but log error
            return None
    
    def get_statistics(self):
        """
        Get current WAF statistics
        
        Returns:
            dict: Statistics including blocked and allowed counts
        """
        total = self.blocked_count + self.allowed_count
        return {
            'total_requests': total,
            'blocked_requests': self.blocked_count,
            'allowed_requests': self.allowed_count,
            'block_rate': (self.blocked_count / total * 100) if total > 0 else 0
        }


# Global WAF instance
waf = WAFInterceptor(threshold=0.7)


def waf_middleware():
    """
    Flask before_request middleware function
    This is called automatically before every request
    """
    # Skip WAF for certain paths (optional)
    if request.path.startswith('/api/admin') or request.path.startswith('/static'):
        return None
    
    # Apply WAF interception
    result = waf.intercept(request)
    
    # If result is not None, request is blocked
    return result


def require_waf_protection(f):
    """
    Decorator to apply WAF protection to specific routes
    
    Usage:
        @app.route('/protected')
        @require_waf_protection
        def protected_route():
            return "This route is protected"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        result = waf.intercept(request)
        if result is not None:
            return result
        return f(*args, **kwargs)
    return decorated_function


# Export functions
__all__ = ['waf_middleware', 'require_waf_protection', 'waf', 'WAFInterceptor']