"""
Complete Test Suite for AI-WAF Database Layer
Person 2: Database Manager
Tests all database operations and API endpoints
Python 3.14 Compatible

Run: python test_database_complete.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_config import init_connection_pool, init_db, test_connection
from database.db_operations import DatabaseOperations
import json


class Colors:
    """Terminal colors for pretty output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_test_header(test_name):
    """Print formatted test header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}TEST: {test_name}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")


def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")


def print_info(message):
    """Print info message"""
    print(f"{Colors.YELLOW}ℹ️  {message}{Colors.END}")


def test_1_connection():
    """Test 1: Database Connection"""
    print_test_header("Database Connection")
    
    try:
        if init_connection_pool():
            print_success("Connection pool created")
        else:
            print_error("Failed to create connection pool")
            return False
        
        if test_connection():
            print_success("Database connection successful")
            return True
        else:
            print_error("Database connection failed")
            return False
            
    except Exception as e:
        print_error(f"Connection test failed: {e}")
        return False


def test_2_table_creation():
    """Test 2: Table Creation"""
    print_test_header("Table Creation")
    
    try:
        if init_db():
            print_success("All 6 tables created successfully")
            print_info("Tables: traffic_logs, attack_patterns, whitelist, blacklist, waf_config, ml_models")
            return True
        else:
            print_error("Failed to create tables")
            return False
            
    except Exception as e:
        print_error(f"Table creation failed: {e}")
        return False


def test_3_log_request():
    """Test 3: Log Request Operation"""
    print_test_header("Log Request Operation")
    
    try:
        db_ops = DatabaseOperations()
        
        # Test logging a benign request
        log_id_1 = db_ops.log_request({
            'ip_address': '192.168.1.100',
            'method': 'GET',
            'url': '/api/users',
            'headers': {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
            'body': '',
            'query_params': {'page': '1', 'limit': '10'},
            'threat_score': 0.15,
            'is_blocked': False,
            'attack_type': None,
            'features': [100, 50, 2, 10, 3.5, 0, 0, 0, 0, 0, 0, 0, 3, 5, 1, 8, 0.2, 0.6, 0, 15],
            'response_time': 0.015
        })
        
        if log_id_1:
            print_success(f"Benign request logged with ID: {log_id_1}")
        else:
            print_error("Failed to log benign request")
            return False
        
        # Test logging a malicious request
        log_id_2 = db_ops.log_request({
            'ip_address': '10.0.0.50',
            'method': 'POST',
            'url': '/login',
            'headers': {'User-Agent': 'Attacker'},
            'body': "username=admin' OR '1'='1",
            'query_params': {},
            'threat_score': 0.95,
            'is_blocked': True,
            'attack_type': 'SQL Injection',
            'features': [200, 75, 1, 25, 5.2, 1, 3, 0, 0, 0, 0, 1, 2, 8, 1, 12, 0.3, 0.5, 0, 10],
            'response_time': 0.008
        })
        
        if log_id_2:
            print_success(f"Malicious request logged with ID: {log_id_2}")
            return True
        else:
            print_error("Failed to log malicious request")
            return False
            
    except Exception as e:
        print_error(f"Log request test failed: {e}")
        return False


def test_4_get_logs():
    """Test 4: Get Logs Operations"""
    print_test_header("Get Logs Operations")
    
    try:
        db_ops = DatabaseOperations()
        
        # Get recent logs
        recent_logs = db_ops.get_recent_logs(limit=5)
        print_success(f"Retrieved {len(recent_logs)} recent logs")
        
        if recent_logs:
            print_info(f"Latest log: IP={recent_logs[0]['ip_address']}, Method={recent_logs[0]['method']}")
        
        # Get attack logs
        attack_logs = db_ops.get_attack_logs(limit=5)
        print_success(f"Retrieved {len(attack_logs)} attack logs")
        
        if attack_logs:
            print_info(f"Latest attack: Type={attack_logs[0]['attack_type']}, Score={attack_logs[0]['threat_score']}")
        
        return True
        
    except Exception as e:
        print_error(f"Get logs test failed: {e}")
        return False


def test_5_statistics():
    """Test 5: Statistics Operations"""
    print_test_header("Statistics Operations")
    
    try:
        db_ops = DatabaseOperations()
        stats = db_ops.get_statistics()
        
        print_success("Statistics retrieved successfully")
        print_info(f"Total Requests: {stats.get('total_requests', 0)}")
        print_info(f"Blocked Requests: {stats.get('blocked_requests', 0)}")
        print_info(f"Requests (24h): {stats.get('requests_24h', 0)}")
        print_info(f"Attacks (24h): {stats.get('attacks_24h', 0)}")
        print_info(f"Avg Threat Score: {stats.get('avg_threat_score', 0):.3f}")
        
        if stats.get('attack_types'):
            print_info(f"Attack Types Detected: {len(stats['attack_types'])}")
        
        return True
        
    except Exception as e:
        print_error(f"Statistics test failed: {e}")
        return False


def test_6_whitelist():
    """Test 6: Whitelist Operations"""
    print_test_header("Whitelist Operations")
    
    try:
        db_ops = DatabaseOperations()
        
        # Add to whitelist
        success = db_ops.add_to_whitelist('192.168.1.1', 'Trusted server', 'admin')
        if success:
            print_success("IP added to whitelist")
        else:
            print_error("Failed to add IP to whitelist")
            return False
        
        # Check whitelist
        is_whitelisted = db_ops.check_whitelist('192.168.1.1')
        if is_whitelisted:
            print_success("IP correctly identified as whitelisted")
        else:
            print_error("Failed to check whitelist")
            return False
        
        # Get all whitelisted IPs
        whitelist = db_ops.get_whitelist()
        print_success(f"Retrieved {len(whitelist)} whitelisted IPs")
        
        return True
        
    except Exception as e:
        print_error(f"Whitelist test failed: {e}")
        return False


def test_7_blacklist():
    """Test 7: Blacklist Operations"""
    print_test_header("Blacklist Operations")
    
    try:
        db_ops = DatabaseOperations()
        
        # Add to blacklist (permanent)
        success = db_ops.add_to_blacklist('10.0.0.1', 'Multiple attack attempts', 'admin')
        if success:
            print_success("IP added to blacklist (permanent)")
        else:
            print_error("Failed to add IP to blacklist")
            return False
        
        # Add to blacklist (temporary - 24 hours)
        success = db_ops.add_to_blacklist('10.0.0.2', 'Suspicious activity', 'admin', expires_hours=24)
        if success:
            print_success("IP added to blacklist (24h expiry)")
        else:
            print_error("Failed to add temporary blacklist entry")
            return False
        
        # Check blacklist
        is_blacklisted = db_ops.check_blacklist('10.0.0.1')
        if is_blacklisted:
            print_success("IP correctly identified as blacklisted")
        else:
            print_error("Failed to check blacklist")
            return False
        
        # Get all blacklisted IPs
        blacklist = db_ops.get_blacklist()
        print_success(f"Retrieved {len(blacklist)} blacklisted IPs")
        
        return True
        
    except Exception as e:
        print_error(f"Blacklist test failed: {e}")
        return False


def test_8_configuration():
    """Test 8: Configuration Operations"""
    print_test_header("Configuration Operations")
    
    try:
        db_ops = DatabaseOperations()
        
        # Get all config
        config = db_ops.get_all_config()
        print_success(f"Retrieved {len(config)} configuration values")
        
        # Get specific config
        threshold = db_ops.get_config('threat_threshold')
        if threshold:
            print_success(f"Threat threshold: {threshold}")
        
        # Update config
        success = db_ops.update_config('threat_threshold', '0.75')
        if success:
            print_success("Configuration updated successfully")
        
        # Verify update
        new_threshold = db_ops.get_config('threat_threshold')
        if new_threshold == '0.75':
            print_success(f"Configuration verified: {new_threshold}")
            return True
        else:
            print_error("Configuration update verification failed")
            return False
        
    except Exception as e:
        print_error(f"Configuration test failed: {e}")
        return False


def test_9_ml_models():
    """Test 9: ML Model Metadata Operations"""
    print_test_header("ML Model Metadata Operations")
    
    try:
        db_ops = DatabaseOperations()
        
        # Save model metadata
        success = db_ops.save_model_metadata(
            model_name='random_forest_classifier',
            model_version='1.0',
            accuracy=0.95,
            file_path='data/trained_models/rf_model.pkl',
            description='Random Forest classifier for attack detection'
        )
        
        if success:
            print_success("Model metadata saved")
        else:
            print_error("Failed to save model metadata")
            return False
        
        # Get latest model
        model = db_ops.get_latest_model('random_forest_classifier')
        if model:
            print_success(f"Retrieved model: v{model['model_version']}, accuracy={model['accuracy']}")
        else:
            print_error("Failed to retrieve model")
            return False
        
        # Get all models
        all_models = db_ops.get_all_models()
        print_success(f"Retrieved {len(all_models)} ML models")
        
        return True
        
    except Exception as e:
        print_error(f"ML models test failed: {e}")
        return False


def test_10_person1_integration():
    """Test 10: Person 1 Integration Check"""
    print_test_header("Person 1 Integration Check")
    
    try:
        db_ops = DatabaseOperations()
        
        print_info("Simulating Person 1's typical workflow...")
        
        # Step 1: Check if IP is whitelisted
        ip = '192.168.1.50'
        is_whitelisted = db_ops.check_whitelist(ip)
        print_success(f"Whitelist check for {ip}: {is_whitelisted}")
        
        # Step 2: Check if IP is blacklisted
        is_blacklisted = db_ops.check_blacklist(ip)
        print_success(f"Blacklist check for {ip}: {is_blacklisted}")
        
        # Step 3: Log the request
        log_id = db_ops.log_request({
            'ip_address': ip,
            'method': 'POST',
            'url': '/api/data',
            'headers': {'User-Agent': 'Test Agent'},
            'body': 'test data',
            'query_params': {},
            'threat_score': 0.45,
            'is_blocked': False,
            'attack_type': None,
            'features': [150, 60, 3, 15, 4.0, 0, 0, 0, 0, 0, 0, 1, 4, 6, 1, 10, 0.25, 0.65, 0, 20],
            'response_time': 0.018
        })
        
        if log_id:
            print_success(f"Request logged successfully (ID: {log_id})")
            print_success("✅ Person 1 integration ready!")
            return True
        else:
            print_error("Failed to log request")
            return False
        
    except Exception as e:
        print_error(f"Person 1 integration test failed: {e}")
        return False


def run_all_tests():
    """Run all tests and generate report"""
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"🧪 AI-WAF DATABASE COMPLETE TEST SUITE")
    print(f"{'='*60}{Colors.END}\n")
    
    tests = [
        ("Database Connection", test_1_connection),
        ("Table Creation", test_2_table_creation),
        ("Log Request", test_3_log_request),
        ("Get Logs", test_4_get_logs),
        ("Statistics", test_5_statistics),
        ("Whitelist Operations", test_6_whitelist),
        ("Blacklist Operations", test_7_blacklist),
        ("Configuration", test_8_configuration),
        ("ML Model Metadata", test_9_ml_models),
        ("Person 1 Integration", test_10_person1_integration)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"📊 TEST SUMMARY")
    print(f"{'='*60}{Colors.END}\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Colors.GREEN}✅ PASSED{Colors.END}" if result else f"{Colors.RED}❌ FAILED{Colors.END}"
        print(f"{test_name:.<40} {status}")
    
    print(f"\n{Colors.BOLD}{'='*60}")
    if passed == total:
        print(f"{Colors.GREEN}🎉 ALL TESTS PASSED! ({passed}/{total}){Colors.END}")
        print(f"{Colors.GREEN}✅ Database layer is ready for integration!{Colors.END}")
    else:
        print(f"{Colors.YELLOW}⚠️  {passed}/{total} tests passed{Colors.END}")
        print(f"{Colors.RED}❌ {total - passed} tests failed{Colors.END}")
    print(f"{'='*60}{Colors.END}\n")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)