"""
AI-WAF Main Application - Fully Integrated
Integrates: Person 1 (WAF), Person 2 (Database), Person 3 (ML Models)
Python 3.14 Compatible

This application combines:
- WAF Interceptor (Person 1) - Traffic protection
- Database Operations (Person 2) - Data persistence
- ML Models (Person 3) - AI-powered threat detection
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import atexit
import sys
import os

# Fix Unicode encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# PERSON 2: DATABASE INITIALIZATION
# ============================================================================
try:
    from database.db_config import init_connection_pool, init_db, close_db
    print("✅ Database modules imported")
    DB_AVAILABLE = True
except Exception as e:
    print(f"⚠️  Database modules not available: {e}")
    DB_AVAILABLE = False

# ============================================================================
# PERSON 2: ADMIN API ROUTES
# ============================================================================
try:
    from routes.admin import admin_bp
    print("✅ Admin API routes imported")
    ADMIN_API_AVAILABLE = True
except Exception as e:
    print(f"⚠️  Admin API routes not available: {e}")
    ADMIN_API_AVAILABLE = False

# ============================================================================
# PERSON 1: WAF MIDDLEWARE
# ============================================================================
try:
    from middleware.waf_interceptor import waf_middleware, waf
    print("✅ WAF middleware imported")
    WAF_AVAILABLE = True
except Exception as e:
    print(f"⚠️  WAF middleware not available: {e}")
    WAF_AVAILABLE = False

# ============================================================================
# PERSON 3: ML MODELS (Loaded by WAF interceptor)
# ============================================================================
# ML models are loaded automatically by waf_interceptor.py
# No need to import them here

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

# Create Flask app
app = Flask(__name__)

# Enable CORS for frontend integration
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Change to specific domain in production
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['SECRET_KEY'] = 'ai-waf-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

@app.before_request
def initialize_system():
    """Initialize all system components before first request"""
    print("\n" + "="*70)
    print("🚀 INITIALIZING AI-WAF SYSTEM")
    print("="*70)
    
    # Initialize database
    if DB_AVAILABLE:
        logger.info("🔧 Initializing database...")
        
        if init_connection_pool():
            logger.info("✅ Database connection pool created")
            
            if init_db():
                logger.info("✅ Database tables initialized")
            else:
                logger.warning("⚠️  Failed to initialize database tables")
        else:
            logger.warning("⚠️  Failed to create database connection pool")
    else:
        logger.warning("⚠️  Database not available - running without persistence")
    
    # WAF status
    if WAF_AVAILABLE:
        logger.info("✅ WAF protection enabled")
        if hasattr(waf, 'ml_available') and waf.ml_available:
            logger.info("✅ AI-powered threat detection active")
        else:
            logger.warning("⚠️  Running with rule-based detection only")
    else:
        logger.warning("⚠️  WAF protection not available")
    
    print("="*70)
    print("🎉 AI-WAF SYSTEM READY!")
    print("="*70 + "\n")

# ============================================================================
# WAF MIDDLEWARE APPLICATION
# ============================================================================

@app.before_request
def apply_waf_protection():
    """
    Apply WAF protection to all incoming requests
    Exceptions: Admin routes, health checks, static files
    """
    # Skip WAF for these paths
    exempt_paths = [
        '/health',
        '/docs',
        '/api/admin',
        '/static'
    ]
    
    # Check if request path should be protected
    should_protect = True
    for exempt_path in exempt_paths:
        if request.path.startswith(exempt_path):
            should_protect = False
            break
    
    # Apply WAF if protection is needed and available
    if should_protect and WAF_AVAILABLE:
        result = waf.intercept(request)
        if result is not None:
            # Request was blocked by WAF
            return result
    
    # Allow request to proceed
    return None

# ============================================================================
# REGISTER BLUEPRINTS
# ============================================================================

# Register Admin API routes
if ADMIN_API_AVAILABLE:
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    logger.info("✅ Admin API registered at /api/admin")

# Register traffic monitoring routes (Person 1)
try:
    from routes.traffic import traffic_bp
    app.register_blueprint(traffic_bp, url_prefix='/api/traffic')
    logger.info("✅ Traffic API registered at /api/traffic")
except Exception as e:
    logger.warning(f"⚠️  Traffic routes not available: {e}")


# ============================================================================
# ROOT ENDPOINTS
# ============================================================================

@app.route('/')
def home():
    """API home endpoint with system status and available routes"""
    return jsonify({
        'message': 'AI-WAF Backend API',
        'status': 'running',
        'version': '1.0.0',
        'system_status': {
            'waf_protection': 'enabled' if WAF_AVAILABLE else 'disabled',
            'ml_detection': 'enabled' if (WAF_AVAILABLE and hasattr(waf, 'ml_available') and waf.ml_available) else 'disabled',
            'database': 'connected' if DB_AVAILABLE else 'disconnected',
            'admin_api': 'enabled' if ADMIN_API_AVAILABLE else 'disabled'
        },
        'components': {
            'person_1': 'WAF Traffic Interceptor & Feature Extraction',
            'person_2': 'Database Operations & Admin API',
            'person_3': 'ML Models (Random Forest + Isolation Forest)'
        },
        'endpoints': {
            'home': '/',
            'health': '/health',
            'docs': '/docs',
            'admin_api': '/api/admin/*',
            'statistics': '/api/admin/stats',
            'logs': '/api/admin/logs',
            'attacks': '/api/admin/attacks',
            'whitelist': '/api/admin/whitelist',
            'blacklist': '/api/admin/blacklist',
            'config': '/api/admin/config',
            'models': '/api/admin/models'
        },
        'quick_links': {
            'dashboard_stats': 'http://localhost:5000/api/admin/stats',
            'recent_attacks': 'http://localhost:5000/api/admin/attacks',
            'health_check': 'http://localhost:5000/health'
        }
    }), 200

@app.route('/health')
def health_check():
    """System health check endpoint"""
    health_status = {
        'status': 'healthy',
        'service': 'AI-WAF Backend',
        'components': {
            'waf': 'operational' if WAF_AVAILABLE else 'unavailable',
            'database': 'connected' if DB_AVAILABLE else 'disconnected',
            'ml_models': 'loaded' if (WAF_AVAILABLE and hasattr(waf, 'ml_available') and waf.ml_available) else 'not loaded',
            'admin_api': 'operational' if ADMIN_API_AVAILABLE else 'unavailable'
        }
    }
    
    # Get WAF statistics if available
    if WAF_AVAILABLE:
        try:
            waf_stats = waf.get_statistics()
            health_status['waf_stats'] = waf_stats
        except:
            pass
    
    # Determine overall health status
    critical_components = [WAF_AVAILABLE, DB_AVAILABLE]
    if not all(critical_components):
        health_status['status'] = 'degraded'
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

@app.route('/docs')
def api_docs():
    """Comprehensive API documentation"""
    return jsonify({
        'api_version': '1.0.0',
        'description': 'AI-powered Web Application Firewall with ML-based threat detection',
        'base_url': '/api',
        'authentication': 'None (Add authentication for production)',
        
        'admin_api': {
            'base': '/api/admin',
            'description': 'Administrative endpoints for WAF management',
            'endpoints': {
                'dashboard': {
                    'GET /stats': {
                        'description': 'Get dashboard statistics',
                        'response': 'Statistics including total requests, blocked requests, attack types, etc.'
                    },
                    'GET /health': {
                        'description': 'Health check',
                        'response': 'System health status'
                    }
                },
                'traffic_logs': {
                    'GET /logs': {
                        'description': 'Get recent traffic logs',
                        'params': '?limit=100&offset=0',
                        'response': 'Paginated list of traffic logs'
                    },
                    'GET /logs/:id': {
                        'description': 'Get specific log details',
                        'response': 'Detailed log information'
                    },
                    'GET /attacks': {
                        'description': 'Get recent attack logs',
                        'params': '?limit=100',
                        'response': 'List of blocked/attack requests'
                    }
                },
                'whitelist': {
                    'GET /whitelist': {
                        'description': 'Get all whitelisted IPs',
                        'response': 'List of whitelisted IP addresses'
                    },
                    'POST /whitelist': {
                        'description': 'Add IP to whitelist',
                        'body': '{"ip_address": "192.168.1.1", "reason": "Office IP"}',
                        'response': 'Success message'
                    },
                    'DELETE /whitelist/:ip': {
                        'description': 'Remove IP from whitelist',
                        'response': 'Success message'
                    }
                },
                'blacklist': {
                    'GET /blacklist': {
                        'description': 'Get all blacklisted IPs',
                        'response': 'List of blacklisted IP addresses'
                    },
                    'POST /blacklist': {
                        'description': 'Add IP to blacklist',
                        'body': '{"ip_address": "10.0.0.1", "reason": "Attack attempts", "expires_hours": 24}',
                        'response': 'Success message'
                    },
                    'DELETE /blacklist/:ip': {
                        'description': 'Remove IP from blacklist',
                        'response': 'Success message'
                    }
                },
                'configuration': {
                    'GET /config': {
                        'description': 'Get WAF configuration',
                        'response': 'Configuration key-value pairs'
                    },
                    'PUT /config': {
                        'description': 'Update WAF configuration',
                        'body': '{"threat_threshold": "0.8"}',
                        'response': 'Success message'
                    }
                },
                'ml_models': {
                    'GET /models': {
                        'description': 'Get ML models metadata',
                        'response': 'List of trained models with accuracy metrics'
                    }
                }
            }
        },
        
        'ml_models': {
            'description': 'AI-powered threat detection',
            'models': [
                {
                    'name': 'Random Forest Classifier',
                    'purpose': 'Classify requests as benign or malicious',
                    'attacks_detected': ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal']
                },
                {
                    'name': 'Isolation Forest',
                    'purpose': 'Detect anomalies and zero-day attacks',
                    'attacks_detected': ['Unknown patterns', 'Anomalous behavior']
                }
            ]
        },
        
        'features': {
            'waf_protection': 'Real-time request interception and analysis',
            'ml_detection': '20 features extracted from each request',
            'dual_model': 'Random Forest + Isolation Forest for maximum accuracy',
            'rule_based_fallback': 'Regex-based detection if ML models unavailable',
            'whitelist_blacklist': 'IP-based access control',
            'database_logging': 'All requests logged for analysis',
            'rate_limiting': 'Protection against DDoS',
            'admin_dashboard': 'Real-time statistics and management'
        }
    }), 200

# ============================================================================
# TEST ENDPOINTS (For demonstration)
# ============================================================================

@app.route('/test/safe')
def test_safe():
    """Test endpoint - Safe request"""
    return jsonify({
        'message': 'This is a safe endpoint',
        'protected_by': 'AI-WAF',
        'status': 'allowed'
    }), 200

@app.route('/test/sql-injection')
def test_sql_injection():
    """Test endpoint - Simulated SQL injection (will be blocked)"""
    # This endpoint should be blocked by WAF
    query = request.args.get('q', '')
    return jsonify({
        'message': 'If you see this, WAF did not block the request',
        'query': query
    }), 200

@app.route('/test/xss')
def test_xss():
    """Test endpoint - Simulated XSS (will be blocked)"""
    # This endpoint should be blocked by WAF
    text = request.args.get('text', '')
    return jsonify({
        'message': 'If you see this, WAF did not block the request',
        'text': text
    }), 200

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'message': 'The requested URL was not found on the server.',
        'available_endpoints': {
            'home': '/',
            'health': '/health',
            'docs': '/docs',
            'admin_api': '/api/admin/*'
        }
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An unexpected error occurred. Please try again later.'
    }), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {error}", exc_info=True)
    return jsonify({
        'success': False,
        'error': 'An error occurred',
        'message': str(error)
    }), 500

# ============================================================================
# CLEANUP ON SHUTDOWN
# ============================================================================

def cleanup():
    """Cleanup function to close database connections and other resources"""
    logger.info("🛑 Shutting down AI-WAF Backend...")
    
    if DB_AVAILABLE:
        try:
            close_db()
            logger.info("✅ Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
    
    logger.info("✅ Shutdown complete")

# Register cleanup function
atexit.register(cleanup)

# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 STARTING AI-WAF BACKEND SERVER")
    print("="*70)
    print("\n📊 SYSTEM COMPONENTS:")
    print(f"   • Person 1 (WAF): {'✅ Loaded' if WAF_AVAILABLE else '❌ Not Available'}")
    print(f"   • Person 2 (Database): {'✅ Loaded' if DB_AVAILABLE else '❌ Not Available'}")
    print(f"   • Person 3 (ML Models): {'✅ Loaded' if (WAF_AVAILABLE and hasattr(waf, 'ml_available') and waf.ml_available) else '❌ Not Available'}")
    print(f"   • Admin API: {'✅ Loaded' if ADMIN_API_AVAILABLE else '❌ Not Available'}")
    
    print("\n🌐 SERVER INFORMATION:")
    print(f"   📍 Server URL: http://localhost:5000")
    print(f"   📍 Health Check: http://localhost:5000/health")
    print(f"   📍 API Documentation: http://localhost:5000/docs")
    print(f"   📍 Admin API: http://localhost:5000/api/admin")
    print(f"   📍 Dashboard Stats: http://localhost:5000/api/admin/stats")
    
    print("\n🧪 TEST ENDPOINTS:")
    print(f"   • Safe Request: http://localhost:5000/test/safe")
    print(f"   • SQL Injection Test: http://localhost:5000/test/sql-injection?q=1' OR '1'='1")
    print(f"   • XSS Test: http://localhost:5000/test/xss?text=<script>alert('xss')</script>")
    
    print("\n" + "="*70 + "\n")
    
    # Run Flask development server
    app.run(
        host='0.0.0.0',  # Accessible from network
        port=5000,
        debug=True,  # Enable debug mode for development
        use_reloader=True  # Auto-reload on code changes
    )