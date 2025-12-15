"""
Feature Extraction Module
Author: Person 1 (Traffic Interceptor & Feature Extraction)
Purpose: Extract 20 numerical features from HTTP requests for ML model

CRITICAL: These 20 features MUST match exactly with Person 3's ML model training!
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs


class FeatureExtractor:
    """
    Extracts 20 features from HTTP requests for threat detection
    """
    
    def __init__(self):
        """Initialize feature extractor with detection patterns"""
        
        # SQL Injection keywords
        self.sql_keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'create', 'alter', 'exec', 'execute', 'script', 'javascript',
            'concat', 'char', 'varchar', 'nchar', 'nvarchar', 'syscolumns',
            'sysobjects', 'xp_', 'sp_', 'declare', 'cast', 'convert',
            'where', 'from', 'table', 'database', 'column', 'or', 'and',
            '--', '/*', '*/', '@@', '@'
        ]
        
        # XSS (Cross-Site Scripting) patterns
        self.xss_patterns = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', 'onfocus=', 'onblur=', '<iframe',
            '</iframe>', 'alert(', 'prompt(', 'confirm(', 'document.cookie',
            'document.write', 'eval(', '<img', '<body', '<svg', '<embed',
            '<object', 'vbscript:', 'expression(', '<style'
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            '../', '..\\', '..%2f', '..%5c', '%2e%2e/', '%2e%2e\\',
            '..../', '....\\', './../', '.\\..\\', '..;/', '..%00/'
        ]
        
        # Command Injection characters
        self.command_injection_chars = [
            ';', '|', '&', '`', '$', '(', ')', '{', '}', 
            '\n', '\r', '>', '<', '||', '&&', '${', '$(', '`'
        ]
        
        # HTTP methods mapping
        self.method_map = {
            'GET': 0,
            'POST': 1,
            'PUT': 2,
            'DELETE': 3,
            'PATCH': 4,
            'OPTIONS': 5,
            'HEAD': 6
        }
    
    def calculate_entropy(self, text):
        """
        Calculate Shannon entropy of a string
        Higher entropy = more random/suspicious
        
        Args:
            text (str): Input text
            
        Returns:
            float: Entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def count_special_characters(self, text):
        """
        Count special characters in text
        
        Args:
            text (str): Input text
            
        Returns:
            int: Number of special characters
        """
        special_chars = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
        return len(re.findall(special_chars, text))
    
    def has_sql_keywords(self, text):
        """
        Check if text contains SQL keywords (case-insensitive)
        
        Args:
            text (str): Input text
            
        Returns:
            tuple: (has_keywords (0/1), keyword_count)
        """
        text_lower = text.lower()
        count = sum(1 for keyword in self.sql_keywords if keyword in text_lower)
        return (1 if count > 0 else 0, count)
    
    def has_xss_patterns(self, text):
        """
        Check if text contains XSS patterns (case-insensitive)
        
        Args:
            text (str): Input text
            
        Returns:
            tuple: (has_patterns (0/1), pattern_count)
        """
        text_lower = text.lower()
        count = sum(1 for pattern in self.xss_patterns if pattern in text_lower)
        return (1 if count > 0 else 0, count)
    
    def has_path_traversal(self, text):
        """
        Check if text contains path traversal patterns
        
        Args:
            text (str): Input text
            
        Returns:
            int: 1 if found, 0 otherwise
        """
        text_lower = text.lower()
        for pattern in self.path_traversal_patterns:
            if pattern in text_lower:
                return 1
        return 0
    
    def has_command_injection(self, text):
        """
        Check if text contains command injection characters
        
        Args:
            text (str): Input text
            
        Returns:
            int: 1 if found, 0 otherwise
        """
        for char in self.command_injection_chars:
            if char in text:
                return 1
        return 0
    
    def encode_http_method(self, method):
        """
        Convert HTTP method to numerical value
        
        Args:
            method (str): HTTP method
            
        Returns:
            int: Encoded method
        """
        return self.method_map.get(method.upper(), 7)  # 7 for unknown methods
    
    def count_dots(self, text):
        """Count number of dots in text"""
        return text.count('.')
    
    def count_slashes(self, text):
        """Count number of slashes (forward and backward)"""
        return text.count('/') + text.count('\\')
    
    def has_digits(self, text):
        """Check if text contains digits"""
        return 1 if any(char.isdigit() for char in text) else 0
    
    def count_digits(self, text):
        """Count number of digits in text"""
        return sum(1 for char in text if char.isdigit())
    
    def calculate_case_ratios(self, text):
        """
        Calculate uppercase and lowercase character ratios
        
        Args:
            text (str): Input text
            
        Returns:
            tuple: (uppercase_ratio, lowercase_ratio)
        """
        if not text:
            return 0.0, 0.0
        
        alpha_chars = [c for c in text if c.isalpha()]
        if not alpha_chars:
            return 0.0, 0.0
        
        upper_count = sum(1 for c in alpha_chars if c.isupper())
        lower_count = sum(1 for c in alpha_chars if c.islower())
        total = len(alpha_chars)
        
        upper_ratio = round(upper_count / total, 4)
        lower_ratio = round(lower_count / total, 4)
        
        return upper_ratio, lower_ratio
    
    def count_hex_chars(self, text):
        """
        Count hexadecimal characters (0-9, A-F, a-f)
        
        Args:
            text (str): Input text
            
        Returns:
            int: Number of hex characters
        """
        hex_pattern = r'[0-9A-Fa-f]'
        return len(re.findall(hex_pattern, text))
    
    def extract_features(self, request_data):
        """
        Extract all 20 features from request data
        
        Args:
            request_data (dict): Request data containing url, method, body, etc.
            
        Returns:
            list: 20 numerical features in exact order
        """
        # Combine all relevant text for analysis
        url = request_data.get('url', '')
        path = request_data.get('path', '')
        query_string = request_data.get('query_string', '')
        body = request_data.get('body', '')
        method = request_data.get('method', 'GET')
        
        # Full request text (for entropy and character analysis)
        full_text = f"{url}{body}"
        
        # Parse URL components
        parsed_url = urlparse(url)
        query_params = parse_qs(query_string)
        
        # FEATURE 1: request_length
        request_length = len(full_text)
        
        # FEATURE 2: url_length
        url_length = len(url)
        
        # FEATURE 3: num_parameters
        num_parameters = len(query_params)
        
        # FEATURE 4: special_char_count
        special_char_count = self.count_special_characters(full_text)
        
        # FEATURE 5: entropy
        entropy = self.calculate_entropy(full_text)
        
        # FEATURES 6-7: SQL keywords
        has_sql, sql_count = self.has_sql_keywords(full_text)
        
        # FEATURES 8-9: XSS patterns
        has_xss, xss_count = self.has_xss_patterns(full_text)
        
        # FEATURE 10: path_traversal
        has_path_trav = self.has_path_traversal(full_text)
        
        # FEATURE 11: command_injection
        has_cmd_inj = self.has_command_injection(full_text)
        
        # FEATURE 12: method_encoded
        method_encoded = self.encode_http_method(method)
        
        # FEATURE 13: num_dots
        num_dots = self.count_dots(full_text)
        
        # FEATURE 14: num_slashes
        num_slashes = self.count_slashes(full_text)
        
        # FEATURE 15: has_digits
        has_digs = self.has_digits(full_text)
        
        # FEATURE 16: digit_count
        digit_count = self.count_digits(full_text)
        
        # FEATURES 17-18: case ratios
        upper_ratio, lower_ratio = self.calculate_case_ratios(full_text)
        
        # FEATURE 19: hex_char_count
        hex_count = self.count_hex_chars(full_text)
        
        # FEATURE 20: query_string_length
        query_string_length = len(query_string)
        
        # Compile all 20 features in EXACT ORDER
        features = [
            request_length,      # 1
            url_length,          # 2
            num_parameters,      # 3
            special_char_count,  # 4
            entropy,             # 5
            has_sql,             # 6
            sql_count,           # 7
            has_xss,             # 8
            xss_count,           # 9
            has_path_trav,       # 10
            has_cmd_inj,         # 11
            method_encoded,      # 12
            num_dots,            # 13
            num_slashes,         # 14
            has_digs,            # 15
            digit_count,         # 16
            upper_ratio,         # 17
            lower_ratio,         # 18
            hex_count,           # 19
            query_string_length  # 20
        ]
        
        return features
    
    def get_feature_names(self):
        """
        Get list of feature names (for documentation/debugging)
        
        Returns:
            list: Names of all 20 features
        """
        return [
            'request_length',
            'url_length',
            'num_parameters',
            'special_char_count',
            'entropy',
            'has_sql_keywords',
            'sql_keyword_count',
            'has_xss_patterns',
            'xss_keyword_count',
            'has_path_traversal',
            'has_command_injection_chars',
            'method_encoded',
            'num_dots',
            'num_slashes',
            'has_digits',
            'digit_count',
            'upper_case_ratio',
            'lower_case_ratio',
            'hex_char_count',
            'query_string_length'
        ]
    
    def features_to_dict(self, features):
        """
        Convert feature list to named dictionary (for debugging)
        
        Args:
            features (list): List of 20 features
            
        Returns:
            dict: Dictionary mapping feature names to values
        """
        names = self.get_feature_names()
        return dict(zip(names, features))


# Standalone testing function
if __name__ == "__main__":
    """
    Test the feature extractor with sample requests
    Run: python feature_extraction.py
    """
    extractor = FeatureExtractor()
    
    print("="*60)
    print("FEATURE EXTRACTION TESTING")
    print("="*60)
    
    # Test 1: Normal Request
    print("\n[TEST 1] Normal Request:")
    normal_request = {
        'url': 'http://example.com/products?category=electronics',
        'path': '/products',
        'query_string': 'category=electronics',
        'body': '',
        'method': 'GET'
    }
    features = extractor.extract_features(normal_request)
    print(f"Features: {features}")
    print(f"Feature count: {len(features)}")
    print("Feature breakdown:")
    for name, value in extractor.features_to_dict(features).items():
        print(f"  {name}: {value}")
    
    # Test 2: SQL Injection Attack
    print("\n[TEST 2] SQL Injection Attack:")
    sql_injection_request = {
        'url': "http://example.com/search?q=1' OR '1'='1 UNION SELECT * FROM users--",
        'path': '/search',
        'query_string': "q=1' OR '1'='1 UNION SELECT * FROM users--",
        'body': '',
        'method': 'GET'
    }
    features = extractor.extract_features(sql_injection_request)
    print(f"Features: {features}")
    print("Key indicators:")
    feature_dict = extractor.features_to_dict(features)
    print(f"  SQL Keywords Found: {feature_dict['has_sql_keywords']}")
    print(f"  SQL Keyword Count: {feature_dict['sql_keyword_count']}")
    print(f"  Entropy: {feature_dict['entropy']}")
    
    # Test 3: XSS Attack
    print("\n[TEST 3] XSS Attack:")
    xss_request = {
        'url': 'http://example.com/comment?text=<script>alert("XSS")</script>',
        'path': '/comment',
        'query_string': 'text=<script>alert("XSS")</script>',
        'body': '',
        'method': 'POST'
    }
    features = extractor.extract_features(xss_request)
    print(f"Features: {features}")
    print("Key indicators:")
    feature_dict = extractor.features_to_dict(features)
    print(f"  XSS Patterns Found: {feature_dict['has_xss_patterns']}")
    print(f"  XSS Pattern Count: {feature_dict['xss_keyword_count']}")
    
    # Test 4: Path Traversal
    print("\n[TEST 4] Path Traversal Attack:")
    path_trav_request = {
        'url': 'http://example.com/files?path=../../etc/passwd',
        'path': '/files',
        'query_string': 'path=../../etc/passwd',
        'body': '',
        'method': 'GET'
    }
    features = extractor.extract_features(path_trav_request)
    print(f"Features: {features}")
    print("Key indicators:")
    feature_dict = extractor.features_to_dict(features)
    print(f"  Path Traversal Detected: {feature_dict['has_path_traversal']}")
    print(f"  Dot Count: {feature_dict['num_dots']}")
    print(f"  Slash Count: {feature_dict['num_slashes']}")
    
    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("="*60)