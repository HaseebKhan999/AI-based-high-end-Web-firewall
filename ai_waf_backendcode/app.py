"""
Main Flask Application - AI-Based Web Application Firewall
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Purpose: Entry point for the AI-WAF system

This is the main application file that:
1. Initializes Flask app and configurations
2. Registers all blueprints (routes)
3. Applies WAF middleware to all requests
4. Provides basic endpoints for testing
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import os
import sys
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import WAF components
from middleware.waf_interceptor import waf_middleware, waf
from routes.traffic import traffic_bp

# Import config
try:
    from config import Config
except ImportError:
    print("[WARNING] config.py not found, using default configuration")
    class Config:
        SECRET_KEY = 'dev-secret-key-change-in-production'
        DEBUG = True
        THREAT_THRESHOLD = 0.7


def create_app(config_class=Config):
    """
    Application factory pattern
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Flask app instance
    """
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Enable CORS for frontend integration
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://localhost:5173"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Apply WAF middleware to all requests
    # This will intercept and analyze every incoming request
    @app.before_request
    def apply_waf():
        """Apply WAF protection before every request"""
        # Skip WAF for admin endpoints and static files
        if request.path.startswith('/api/admin') or \
           request.path.startswith('/static') or \
           request.path.startswith('/favicon.ico') or \
           request.path == '/health':
            return None
        
        # Apply WAF interception
        return waf_middleware()
    
    # Register blueprints
    app.register_blueprint(traffic_bp, url_prefix='/api/traffic')
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status': 500
        }), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'error': 'Forbidden',
            'message': 'Access denied by WAF',
            'status': 403
        }), 403
    
    # Basic routes
    @app.route('/')
    def index():
        """Welcome page with API information"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI-WAF System</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    max-width: 1000px;
                    margin: 50px auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }
                .container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
                }
                h1 { margin-top: 0; font-size: 2.5em; }
                h2 { color: #ffd700; margin-top: 30px; }
                .endpoint {
                    background: rgba(0, 0, 0, 0.2);
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 8px;
                    border-left: 4px solid #ffd700;
                }
                .method {
                    display: inline-block;
                    padding: 5px 10px;
                    background: #4CAF50;
                    border-radius: 4px;
                    font-weight: bold;
                    margin-right: 10px;
                }
                .method.post { background: #2196F3; }
                .method.delete { background: #f44336; }
                code {
                    background: rgba(0, 0, 0, 0.3);
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }
                .stat-box {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }
                .stat-value {
                    font-size: 2em;
                    font-weight: bold;
                    color: #ffd700;
                }
                .stat-label {
                    font-size: 0.9em;
                    opacity: 0.8;
                }
                .status-badge {
                    display: inline-block;
                    padding: 8px 16px;
                    background: #4CAF50;
                    border-radius: 20px;
                    font-weight: bold;
                    margin: 10px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ AI-Based Web Application Firewall</h1>
                <div class="status-badge">✓ WAF Active</div>
                
                <p>Welcome to the AI-WAF system. This firewall uses machine learning to protect web applications from various attacks including SQL injection, XSS, path traversal, and command injection.</p>
                
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value">{{ stats.total_requests }}</div>
                        <div class="stat-label">Total Requests</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{{ stats.blocked_requests }}</div>
                        <div class="stat-label">Blocked</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{{ stats.allowed_requests }}</div>
                        <div class="stat-label">Allowed</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{{ "%.1f"|format(stats.block_rate) }}%</div>
                        <div class="stat-label">Block Rate</div>
                    </div>
                </div>
                
                <h2>📡 Available API Endpoints</h2>
                
                <div class="endpoint">
                    <span class="method">GET</span>
                    <code>/api/traffic/stats</code>
                    <p>Get real-time WAF statistics</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/traffic/test</code>
                    <p>Test WAF with custom requests</p>
                </div>
                
                <div class="endpoint">
                    <span class="method">GET</span>
                    <code>/api/traffic/logs</code>
                    <p>Retrieve traffic logs (requires database)</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/traffic/whitelist</code>
                    <p>Add IP to whitelist</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/traffic/blacklist</code>
                    <p>Add IP to blacklist</p>
                </div>
                
                <div class="endpoint">
                    <span class="method">GET</span>
                    <code>/health</code>
                    <p>Health check endpoint</p>
                </div>
                
                <h2>🧪 Testing the WAF</h2>
                <p>Try these example attacks to test the WAF:</p>
                
                <div class="endpoint">
                    <strong>SQL Injection:</strong><br>
                    <code>GET /search?q=1' OR '1'='1</code>
                </div>
                
                <div class="endpoint">
                    <strong>XSS Attack:</strong><br>
                    <code>GET /comment?text=&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                </div>
                
                <div class="endpoint">
                    <strong>Path Traversal:</strong><br>
                    <code>GET /file?path=../../etc/passwd</code>
                </div>
                
                <p style="margin-top: 40px; text-align: center; opacity: 0.7;">
                    <small>AI-WAF System v1.0 | Infosec Project 2024</small>
                </p>
            </div>
        </body>
        </html>
        """
        stats = waf.get_statistics()
        return render_template_string(html, stats=stats)
    
    @app.route('/health')
    def health_check():
        """Health check endpoint (bypasses WAF)"""
        return jsonify({
            'status': 'healthy',
            'waf_active': True,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }), 200
    
    @app.route('/api/status')
    def api_status():
        """API status and configuration"""
        return jsonify({
            'waf_enabled': True,
            'threat_threshold': waf.threshold,
            'ml_model_loaded': False,  # Will be True when Person 3 integrates
            'database_connected': False,  # Will be True when Person 2 integrates
            'features_count': 20,
            'statistics': waf.get_statistics()
        }), 200
    
    # Protected test routes (these will be analyzed by WAF)
    @app.route('/search')
    def search():
        """Test endpoint - search functionality"""
        query = request.args.get('q', '')
        return jsonify({
            'message': 'Search successful',
            'query': query,
            'results': []
        }), 200
    
    @app.route('/comment', methods=['GET', 'POST'])
    def comment():
        """Test endpoint - comment functionality"""
        if request.method == 'POST':
            text = request.json.get('text', '') if request.is_json else request.form.get('text', '')
        else:
            text = request.args.get('text', '')
        
        return jsonify({
            'message': 'Comment received',
            'text': text
        }), 200
    
    @app.route('/file')
    def file_access():
        """Test endpoint - file access"""
        path = request.args.get('path', '')
        return jsonify({
            'message': 'File access',
            'path': path
        }), 200
    
    @app.route('/login', methods=['POST'])
    def login():
        """Test endpoint - login functionality"""
        if request.is_json:
            username = request.json.get('username', '')
            password = request.json.get('password', '')
        else:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
        
        return jsonify({
            'message': 'Login processed',
            'username': username
        }), 200
    
    return app


# Create the app instance
app = create_app()


if __name__ == '__main__':
    """
    Run the application
    
    Usage:
        python app.py
        
    The server will start on http://localhost:5000
    """
    print("="*60)
    print("🛡️  AI-BASED WEB APPLICATION FIREWALL")
    print("="*60)
    print(f"Server starting on http://localhost:5000")
    print(f"WAF Status: ACTIVE")
    print(f"Threat Threshold: {waf.threshold}")
    print(f"Features: 20")
    print("="*60)
    print("\nEndpoints:")
    print("  • http://localhost:5000/              - Welcome page")
    print("  • http://localhost:5000/health        - Health check")
    print("  • http://localhost:5000/api/status    - API status")
    print("  • http://localhost:5000/api/traffic/* - Traffic management")
    print("\nTest Attacks:")
    print("  • SQL: http://localhost:5000/search?q=1' OR '1'='1")
    print("  • XSS: http://localhost:5000/comment?text=<script>alert('XSS')</script>")
    print("  • Path: http://localhost:5000/file?path=../../etc/passwd")
    print("="*60)
    print()
    
    # Run the app
    app.run(
        host='0.0.0.0',  # Listen on all interfaces
        port=5000,
        debug=True,
        use_reloader=True
    )