"""
Traffic Management Routes
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Purpose: API endpoints for traffic monitoring and management

This blueprint provides:
1. Traffic statistics and monitoring
2. Manual IP whitelist/blacklist management
3. Testing endpoints for WAF validation
4. Traffic log retrieval (when database is integrated)
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timezone, timedelta
import sys
import os

# Pakistan timezone (GMT+5)
PKT = timezone(timedelta(hours=5))

def get_current_time():
    """Get current time in Pakistan timezone (GMT+5)"""
    return datetime.now(PKT)

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import WAF components
from middleware.waf_interceptor import waf
from utils.threat_detector import ThreatDetector
from utils.feature_extraction import FeatureExtractor

# Create blueprint
traffic_bp = Blueprint('traffic', __name__)

# Initialize detector and extractor
threat_detector = ThreatDetector()
feature_extractor = FeatureExtractor()


@traffic_bp.route('/stats', methods=['GET'])
def get_statistics():
    """
    Get real-time WAF statistics
    
    Returns:
        JSON with request counts, block rate, and detector stats
    """
    waf_stats = waf.get_statistics()
    detector_stats = threat_detector.get_statistics()
    
    return jsonify({
        'success': True,
        'timestamp': get_current_time().isoformat(),
        'waf_statistics': waf_stats,
        'detector_statistics': detector_stats,
        'threshold': waf.threshold,
        'features_count': 20
    }), 200


@traffic_bp.route('/test', methods=['POST'])
def test_waf():
    """
    Test WAF with custom request data
    
    Request Body (JSON):
    {
        "url": "http://example.com/search?q=test",
        "method": "GET",
        "body": "",
        "ip_address": "192.168.1.1"
    }
    
    Returns:
        Analysis results with threat score and recommendation
    """
    try:
        # Get test data from request
        test_data = request.get_json()
        
        if not test_data:
            return jsonify({
                'success': False,
                'error': 'No test data provided',
                'message': 'Please provide request data in JSON format'
            }), 400
        
        # Required fields
        required_fields = ['url', 'method']
        missing_fields = [field for field in required_fields if field not in test_data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Prepare request data
        request_data = {
            'url': test_data.get('url', ''),
            'path': test_data.get('path', '/'),
            'query_string': test_data.get('query_string', ''),
            'method': test_data.get('method', 'GET'),
            'body': test_data.get('body', ''),
            'ip_address': test_data.get('ip_address', '0.0.0.0'),
            'headers': test_data.get('headers', {}),
            'timestamp': get_current_time().isoformat()
        }
        
        # Step 1: Extract features
        features = feature_extractor.extract_features(request_data)
        
        # Step 2: Detect threats
        detection_result = threat_detector.detect_threat(request_data, features)
        
        # Step 3: Determine action
        threat_score = detection_result['threat_score']
        should_block = threat_score > waf.threshold
        threat_level = threat_detector.get_threat_level(threat_score)
        
        # Step 4: Prepare response
        response_data = {
            'success': True,
            'test_result': {
                'request': {
                    'url': request_data['url'],
                    'method': request_data['method'],
                    'ip_address': request_data['ip_address']
                },
                'analysis': {
                    'threat_score': round(threat_score, 4),
                    'attack_type': detection_result['attack_type'],
                    'threat_level': threat_level,
                    'confidence': round(detection_result['confidence'], 4),
                    'detection_method': detection_result['detection_method']
                },
                'decision': {
                    'should_block': should_block,
                    'action': 'BLOCK' if should_block else 'ALLOW',
                    'reason': f"Threat score ({threat_score:.2f}) {'exceeds' if should_block else 'below'} threshold ({waf.threshold})"
                },
                'features': {
                    'count': len(features),
                    'values': features,
                    'names': feature_extractor.get_feature_names()
                }
            },
            'timestamp': get_current_time().isoformat()
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Test failed',
            'message': str(e)
        }), 500


@traffic_bp.route('/logs', methods=['GET'])
def get_traffic_logs():
    """
    Get traffic logs from database
    
    Query Parameters:
        limit (int): Number of logs to retrieve (default: 50)
        offset (int): Offset for pagination (default: 0)
        blocked_only (bool): Return only blocked requests
    
    Returns:
        List of traffic logs
    """
    # TODO: Replace with Person 2's database query
    # from database.db_operations import get_traffic_logs
    # logs = get_traffic_logs(limit, offset, blocked_only)
    
    # Mock response for now
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    blocked_only = request.args.get('blocked_only', 'false').lower() == 'true'
    
    return jsonify({
        'success': True,
        'message': 'Database not integrated yet',
        'logs': [],
        'total': 0,
        'limit': limit,
        'offset': offset,
        'blocked_only': blocked_only,
        'note': 'Waiting for Person 2 to integrate PostgreSQL database'
    }), 200


@traffic_bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """
    Manage IP whitelist
    
    GET: Retrieve all whitelisted IPs
    POST: Add IP to whitelist
        Body: {"ip_address": "192.168.1.100"}
    DELETE: Remove IP from whitelist
        Body: {"ip_address": "192.168.1.100"}
    """
    if request.method == 'GET':
        # Get all whitelisted IPs
        whitelist = threat_detector.get_whitelist()
        return jsonify({
            'success': True,
            'whitelist': whitelist,
            'count': len(whitelist)
        }), 200
    
    elif request.method == 'POST':
        # Add IP to whitelist
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address required'
            }), 400
        
        threat_detector.add_to_whitelist(ip_address)
        
        # TODO: Also add to database (Person 2)
        # from database.db_operations import add_to_whitelist
        # add_to_whitelist(ip_address)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} added to whitelist',
            'ip_address': ip_address
        }), 201
    
    elif request.method == 'DELETE':
        # Remove IP from whitelist
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address required'
            }), 400
        
        success = threat_detector.remove_from_whitelist(ip_address)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from whitelist'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': f'IP {ip_address} not found in whitelist'
            }), 404


@traffic_bp.route('/blacklist', methods=['GET', 'POST', 'DELETE'])
def manage_blacklist():
    """
    Manage IP blacklist
    
    GET: Retrieve all blacklisted IPs
    POST: Add IP to blacklist
        Body: {"ip_address": "10.0.0.666"}
    DELETE: Remove IP from blacklist
        Body: {"ip_address": "10.0.0.666"}
    """
    if request.method == 'GET':
        # Get all blacklisted IPs
        blacklist = threat_detector.get_blacklist()
        return jsonify({
            'success': True,
            'blacklist': blacklist,
            'count': len(blacklist)
        }), 200
    
    elif request.method == 'POST':
        # Add IP to blacklist
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address required'
            }), 400
        
        threat_detector.add_to_blacklist(ip_address)
        
        # TODO: Also add to database (Person 2)
        # from database.db_operations import add_to_blacklist
        # add_to_blacklist(ip_address)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} added to blacklist',
            'ip_address': ip_address
        }), 201
    
    elif request.method == 'DELETE':
        # Remove IP from blacklist
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address required'
            }), 400
        
        success = threat_detector.remove_from_blacklist(ip_address)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from blacklist'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': f'IP {ip_address} not found in blacklist'
            }), 404


@traffic_bp.route('/analyze', methods=['POST'])
def analyze_request():
    """
    Analyze a request without blocking it
    
    Request Body (JSON):
    {
        "url": "http://example.com/search?q=test",
        "method": "GET",
        "body": ""
    }
    
    Returns:
        Detailed analysis with features breakdown
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL required'
            }), 400
        
        # Prepare request data
        request_data = {
            'url': data.get('url', ''),
            'path': data.get('path', '/'),
            'query_string': data.get('query_string', ''),
            'method': data.get('method', 'GET'),
            'body': data.get('body', ''),
            'timestamp': get_current_time().isoformat()
        }
        
        # Extract features
        features = feature_extractor.extract_features(request_data)
        feature_dict = feature_extractor.features_to_dict(features)
        
        # Detect threats
        detection = threat_detector.detect_threat(request_data, features)
        
        return jsonify({
            'success': True,
            'analysis': {
                'request': request_data,
                'features': feature_dict,
                'detection': detection,
                'threat_level': threat_detector.get_threat_level(detection['threat_score']),
                'recommendation': 'BLOCK' if detection['threat_score'] > waf.threshold else 'ALLOW'
            },
            'timestamp': get_current_time().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@traffic_bp.route('/config', methods=['GET', 'PUT'])
def manage_config():
    """
    Get or update WAF configuration
    
    GET: Retrieve current configuration
    PUT: Update configuration
        Body: {"threshold": 0.8, "rate_limit": 150}
    """
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'config': {
                'threat_threshold': waf.threshold,
                'rate_limit': threat_detector.rate_limit_threshold,
                'features_count': 20,
                'ml_model_loaded': threat_detector.ml_predictor is not None
            }
        }), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Update threshold if provided
        if 'threshold' in data:
            new_threshold = float(data['threshold'])
            if 0.0 <= new_threshold <= 1.0:
                waf.threshold = new_threshold
            else:
                return jsonify({
                    'success': False,
                    'error': 'Threshold must be between 0.0 and 1.0'
                }), 400
        
        # Update rate limit if provided
        if 'rate_limit' in data:
            new_rate_limit = int(data['rate_limit'])
            if new_rate_limit > 0:
                threat_detector.rate_limit_threshold = new_rate_limit
            else:
                return jsonify({
                    'success': False,
                    'error': 'Rate limit must be positive'
                }), 400
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated',
            'config': {
                'threat_threshold': waf.threshold,
                'rate_limit': threat_detector.rate_limit_threshold
            }
        }), 200


@traffic_bp.route('/recent', methods=['GET'])
def get_recent_requests():
    """
    Get recent requests (last 10)
    This is a simplified version until database is integrated
    """
    # TODO: Get from database when Person 2 integrates
    return jsonify({
        'success': True,
        'message': 'Database not integrated yet',
        'recent_requests': [],
        'note': 'This endpoint will return recent traffic once PostgreSQL is integrated'
    }), 200


@traffic_bp.route('/clear-stats', methods=['POST'])
def clear_statistics():
    """
    Clear WAF statistics (reset counters)
    """
    waf.blocked_count = 0
    waf.allowed_count = 0
    
    return jsonify({
        'success': True,
        'message': 'Statistics cleared',
        'statistics': waf.get_statistics()
    }), 200


# Export blueprint
__all__ = ['traffic_bp']