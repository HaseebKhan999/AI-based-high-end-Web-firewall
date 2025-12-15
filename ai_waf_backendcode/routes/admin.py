"""
Admin API Routes for AI-WAF Dashboard
Person 2: Database Manager
Flask API endpoints for admin dashboard
Python 3.14 Compatible
"""

from flask import Blueprint, jsonify, request
from database.db_operations import DatabaseOperations
import logging

# Create Blueprint
admin_bp = Blueprint('admin', __name__)
db_ops = DatabaseOperations()

logger = logging.getLogger(__name__)


# ==========================================
# DASHBOARD STATISTICS
# ==========================================

@admin_bp.route('/stats', methods=['GET'])
def get_statistics():
    """
    Get dashboard statistics.
    
    GET /api/admin/stats
    
    Response:
    {
        "success": true,
        "data": {
            "total_requests": 1500,
            "blocked_requests": 45,
            "requests_24h": 230,
            "attacks_24h": 12,
            "avg_threat_score": 0.23,
            "attack_types": [...],
            "top_attackers": [...]
        }
    }
    """
    try:
        stats = db_ops.get_statistics()
        return jsonify({
            'success': True,
            'data': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# TRAFFIC LOGS
# ==========================================

@admin_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Get recent traffic logs with pagination.
    
    GET /api/admin/logs?limit=50&offset=0
    
    Query Parameters:
    - limit: Number of logs to retrieve (default: 100)
    - offset: Number of logs to skip (default: 0)
    
    Response:
    {
        "success": true,
        "data": [
            {
                "id": 1,
                "timestamp": "2024-12-15T10:30:00",
                "ip_address": "192.168.1.1",
                "method": "GET",
                "url": "/search",
                "threat_score": 0.85,
                "is_blocked": true,
                "attack_type": "SQL Injection"
            },
            ...
        ],
        "pagination": {
            "limit": 50,
            "offset": 0,
            "total": 1500
        }
    }
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Limit maximum to prevent overload
        if limit > 500:
            limit = 500
        
        logs = db_ops.get_recent_logs(limit=limit, offset=offset)
        
        # Get total count for pagination
        stats = db_ops.get_statistics()
        total = stats.get('total_requests', 0)
        
        return jsonify({
            'success': True,
            'data': logs,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/logs/<int:log_id>', methods=['GET'])
def get_log_details(log_id):
    """
    Get detailed information about a specific log.
    
    GET /api/admin/logs/123
    
    Response:
    {
        "success": true,
        "data": {
            "id": 123,
            "timestamp": "2024-12-15T10:30:00",
            "ip_address": "192.168.1.1",
            "method": "POST",
            "url": "/login",
            "headers": {...},
            "body": "...",
            "threat_score": 0.92,
            "is_blocked": true,
            "attack_type": "SQL Injection",
            "features": [...],
            "response_time": 0.023
        }
    }
    """
    try:
        log = db_ops.get_log_by_id(log_id)
        
        if log:
            return jsonify({
                'success': True,
                'data': log
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Log not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Error getting log details: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/attacks', methods=['GET'])
def get_attacks():
    """
    Get recent attack/blocked traffic logs.
    
    GET /api/admin/attacks?limit=50
    
    Response:
    {
        "success": true,
        "data": [
            {
                "id": 1,
                "timestamp": "2024-12-15T10:30:00",
                "ip_address": "192.168.1.1",
                "method": "GET",
                "url": "/search",
                "threat_score": 0.92,
                "attack_type": "SQL Injection"
            },
            ...
        ]
    }
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        if limit > 500:
            limit = 500
            
        attacks = db_ops.get_attack_logs(limit=limit)
        
        return jsonify({
            'success': True,
            'data': attacks
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting attacks: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# WHITELIST MANAGEMENT
# ==========================================

@admin_bp.route('/whitelist', methods=['GET'])
def get_whitelist():
    """
    Get all whitelisted IP addresses.
    
    GET /api/admin/whitelist
    
    Response:
    {
        "success": true,
        "data": [
            {
                "id": 1,
                "ip_address": "192.168.1.1",
                "reason": "Trusted server",
                "added_by": "admin",
                "created_at": "2024-12-15T10:00:00"
            },
            ...
        ]
    }
    """
    try:
        whitelist = db_ops.get_whitelist()
        return jsonify({
            'success': True,
            'data': whitelist
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/whitelist', methods=['POST'])
def add_to_whitelist():
    """
    Add an IP address to the whitelist.
    
    POST /api/admin/whitelist
    Content-Type: application/json
    
    Body:
    {
        "ip_address": "192.168.1.1",
        "reason": "Trusted server",
        "added_by": "admin"
    }
    
    Response:
    {
        "success": true,
        "message": "IP added to whitelist"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'ip_address' not in data:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400
        
        ip_address = data['ip_address']
        reason = data.get('reason', 'Manual addition')
        added_by = data.get('added_by', 'admin')
        
        success = db_ops.add_to_whitelist(ip_address, reason, added_by)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} added to whitelist'
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to add IP to whitelist'
            }), 500
            
    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/whitelist/<ip_address>', methods=['DELETE'])
def remove_from_whitelist(ip_address):
    """
    Remove an IP address from the whitelist.
    
    DELETE /api/admin/whitelist/192.168.1.1
    
    Response:
    {
        "success": true,
        "message": "IP removed from whitelist"
    }
    """
    try:
        success = db_ops.remove_from_whitelist(ip_address)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from whitelist'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to remove IP from whitelist'
            }), 500
            
    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# BLACKLIST MANAGEMENT
# ==========================================

@admin_bp.route('/blacklist', methods=['GET'])
def get_blacklist():
    """
    Get all blacklisted IP addresses.
    
    GET /api/admin/blacklist
    
    Response:
    {
        "success": true,
        "data": [
            {
                "id": 1,
                "ip_address": "10.0.0.1",
                "reason": "Multiple attack attempts",
                "added_by": "admin",
                "created_at": "2024-12-15T10:00:00",
                "expires_at": "2024-12-16T10:00:00"
            },
            ...
        ]
    }
    """
    try:
        blacklist = db_ops.get_blacklist()
        return jsonify({
            'success': True,
            'data': blacklist
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting blacklist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/blacklist', methods=['POST'])
def add_to_blacklist():
    """
    Add an IP address to the blacklist.
    
    POST /api/admin/blacklist
    Content-Type: application/json
    
    Body:
    {
        "ip_address": "10.0.0.1",
        "reason": "Multiple attack attempts",
        "added_by": "admin",
        "expires_hours": 24  // optional, null = permanent
    }
    
    Response:
    {
        "success": true,
        "message": "IP added to blacklist"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'ip_address' not in data:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400
        
        ip_address = data['ip_address']
        reason = data.get('reason', 'Manual addition')
        added_by = data.get('added_by', 'admin')
        expires_hours = data.get('expires_hours')
        
        success = db_ops.add_to_blacklist(
            ip_address, reason, added_by, expires_hours
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} added to blacklist'
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to add IP to blacklist'
            }), 500
            
    except Exception as e:
        logger.error(f"Error adding to blacklist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/blacklist/<ip_address>', methods=['DELETE'])
def remove_from_blacklist(ip_address):
    """
    Remove an IP address from the blacklist.
    
    DELETE /api/admin/blacklist/10.0.0.1
    
    Response:
    {
        "success": true,
        "message": "IP removed from blacklist"
    }
    """
    try:
        success = db_ops.remove_from_blacklist(ip_address)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from blacklist'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to remove IP from blacklist'
            }), 500
            
    except Exception as e:
        logger.error(f"Error removing from blacklist: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# CONFIGURATION MANAGEMENT
# ==========================================

@admin_bp.route('/config', methods=['GET'])
def get_config():
    """
    Get all WAF configuration values.
    
    GET /api/admin/config
    
    Response:
    {
        "success": true,
        "data": {
            "threat_threshold": "0.7",
            "enable_blocking": "true",
            "enable_logging": "true",
            ...
        }
    }
    """
    try:
        config = db_ops.get_all_config()
        return jsonify({
            'success': True,
            'data': config
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/config', methods=['PUT'])
def update_config():
    """
    Update WAF configuration values.
    
    PUT /api/admin/config
    Content-Type: application/json
    
    Body:
    {
        "threat_threshold": "0.8",
        "enable_blocking": "true"
    }
    
    Response:
    {
        "success": true,
        "message": "Configuration updated"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400
        
        # Update each config key
        for key, value in data.items():
            db_ops.update_config(key, str(value))
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# ML MODEL MANAGEMENT (For Person 3)
# ==========================================

@admin_bp.route('/models', methods=['GET'])
def get_models():
    """
    Get all ML models metadata.
    
    GET /api/admin/models
    
    Response:
    {
        "success": true,
        "data": [
            {
                "id": 1,
                "model_name": "random_forest_classifier",
                "model_version": "1.0",
                "accuracy": 0.95,
                "file_path": "data/trained_models/rf_model.pkl",
                "created_at": "2024-12-15T10:00:00"
            },
            ...
        ]
    }
    """
    try:
        models = db_ops.get_all_models()
        return jsonify({
            'success': True,
            'data': models
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting models: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==========================================
# HEALTH CHECK
# ==========================================

@admin_bp.route('/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint.
    
    GET /api/admin/health
    
    Response:
    {
        "status": "healthy",
        "database": "connected"
    }
    """
    try:
        # Try to get config to verify database connection
        config = db_ops.get_config('threat_threshold')
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected' if config else 'error'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500