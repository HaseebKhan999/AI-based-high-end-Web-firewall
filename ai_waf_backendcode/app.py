"""
AI-WAF Main Application
Person 2: Database Manager
Main Flask application integrating all components
Python 3.14 Compatible
"""

from flask import Flask, jsonify
from flask_cors import CORS
from database.db_config import init_connection_pool, init_db, close_db
from routes.admin import admin_bp
import logging
import atexit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Enable CORS for frontend integration
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Change this to specific domain in production
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type"]
    }
})

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Initialize database on startup
@app.before_request
def initialize_database():
    """Initialize database connection and tables before first request"""
    logger.info("🔧 Initializing AI-WAF Backend...")
    
    # Create connection pool
    if init_connection_pool():
        logger.info("✅ Database connection pool created")
        
        # Create tables if they don't exist
        if init_db():
            logger.info("✅ Database tables initialized")
        else:
            logger.error("❌ Failed to initialize database tables")
    else:
        logger.error("❌ Failed to create database connection pool")

# Register blueprints
app.register_blueprint(admin_bp, url_prefix='/api/admin')

# TODO: Person 1 will add their routes here
# from routes.traffic import traffic_bp
# app.register_blueprint(traffic_bp, url_prefix='/api/traffic')

# Root endpoint
@app.route('/')
def home():
    """API home endpoint with available routes"""
    return jsonify({
        'message': 'AI-WAF Backend API',
        'status': 'running',
        'version': '1.0.0',
        'components': {
            'database': 'Neon PostgreSQL',
            'framework': 'Flask',
            'python_version': '3.14'
        },
        'endpoints': {
            'admin_api': '/api/admin/*',
            'health_check': '/api/admin/health',
            'statistics': '/api/admin/stats',
            'logs': '/api/admin/logs',
            'attacks': '/api/admin/attacks',
            'whitelist': '/api/admin/whitelist',
            'blacklist': '/api/admin/blacklist',
            'config': '/api/admin/config',
            'models': '/api/admin/models'
        },
        'documentation': {
            'api_docs': '/docs',
            'integration_guide': 'See PERSON2_INTEGRATION_GUIDE.md'
        }
    }), 200

# Health check endpoint
@app.route('/health')
def health_check():
    """Simple health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'AI-WAF Backend',
        'database': 'connected'
    }), 200

# API documentation endpoint
@app.route('/docs')
def api_docs():
    """API documentation"""
    return jsonify({
        'api_version': '1.0.0',
        'base_url': '/api',
        'endpoints': {
            'admin': {
                'base': '/api/admin',
                'routes': {
                    'GET /health': 'Health check',
                    'GET /stats': 'Dashboard statistics',
                    'GET /logs': 'Recent traffic logs (supports ?limit=N&offset=N)',
                    'GET /logs/:id': 'Specific log details',
                    'GET /attacks': 'Recent attack logs',
                    'GET /whitelist': 'Get whitelist',
                    'POST /whitelist': 'Add IP to whitelist',
                    'DELETE /whitelist/:ip': 'Remove IP from whitelist',
                    'GET /blacklist': 'Get blacklist',
                    'POST /blacklist': 'Add IP to blacklist',
                    'DELETE /blacklist/:ip': 'Remove IP from blacklist',
                    'GET /config': 'Get configuration',
                    'PUT /config': 'Update configuration',
                    'GET /models': 'Get ML models metadata'
                }
            }
        }
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'message': 'The requested URL was not found on the server.'
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
    logger.error(f"Unhandled exception: {error}")
    return jsonify({
        'success': False,
        'error': 'An error occurred',
        'message': str(error)
    }), 500

# Cleanup on shutdown
def cleanup():
    """Cleanup function to close database connections"""
    logger.info("🛑 Shutting down AI-WAF Backend...")
    close_db()
    logger.info("✅ Database connections closed")

# Register cleanup function
atexit.register(cleanup)

# Run the application
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting AI-WAF Backend Server")
    print("="*60)
    print(f"📍 Server URL: http://localhost:5000")
    print(f"📍 API Base: http://localhost:5000/api")
    print(f"📍 Admin API: http://localhost:5000/api/admin")
    print(f"📍 Health Check: http://localhost:5000/health")
    print(f"📍 API Docs: http://localhost:5000/docs")
    print("="*60 + "\n")
    
    # Run Flask development server
    app.run(
        host='0.0.0.0',  # Accessible from network
        port=5000,
        debug=True,  # Enable debug mode for development
        use_reloader=True  # Auto-reload on code changes
    )