"""
AI-WAF Main Application
Integration of all components
"""

from flask import Flask
from flask_cors import CORS
from database.db_config import init_connection_pool, init_db
from routes.admin import admin_bp
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Initialize database
logger.info("🔧 Initializing database...")
if init_connection_pool():
    logger.info("✅ Database connection pool created")
    if init_db():
        logger.info("✅ Database tables initialized")
    else:
        logger.error("❌ Failed to initialize database tables")
else:
    logger.error("❌ Failed to create database connection pool")

# Register blueprints
app.register_blueprint(admin_bp, url_prefix='/api/admin')

# TODO: Person 1 will add traffic handler middleware here
# TODO: Person 1 will add traffic routes here

@app.route('/')
def home():
    return {
        'message': 'AI-WAF Backend API',
        'status': 'running',
        'version': '1.0',
        'endpoints': {
            'admin': '/api/admin/*',
            'health': '/api/admin/health'
        }
    }

@app.route('/health')
def health():
    return {'status': 'healthy', 'database': 'connected'}

if __name__ == '__main__':
    logger.info("🚀 Starting AI-WAF Backend Server...")
    app.run(host='0.0.0.0', port=5000, debug=True)