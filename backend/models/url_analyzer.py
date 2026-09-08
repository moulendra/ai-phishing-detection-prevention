"""
URL Analyzer - Rule-based phishing detection for URLs
"""

import re
import urllib.parse
from typing import Dict

class URLAnalyzer:
    """Analyzes URLs for phishing indicators using rule-based detection"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'login', r'signin', r'account', r'banking', r'secure',
            r'verify', r'confirm', r'wallet', r'password'
        ]
        self.suspicious_tlds = ['.xyz', '.top', '.zip', '.tk', '.ml', '.ga', '.cf']
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'paypal.com', 'ebay.com', 'netflix.com'
        ]
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def analyze(self, url: str) -> Dict:
        """Analyze a URL for phishing indicators"""
        result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'details': {'indicators': [], 'risk_factors': [], 'safe_factors': []}
        }
        
        if not self._is_valid_url(url):
            result['details']['risk_factors'].append('Invalid URL format')
            result['confidence_score'] += 0.3
            return result
        
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            result['details']['risk_factors'].append(f'Suspicious TLD: {domain}')
            result['confidence_score'] += 0.3
            result['details']['indicators'].append('suspicious_tld')
        
        # Suspicious keywords
        for pattern in self.suspicious_patterns:
            if pattern in domain:
                result['details']['risk_factors'].append(f'Suspicious keyword: {pattern}')
                result['confidence_score'] += 0.2
                result['details']['indicators'].append('suspicious_keyword')
        
        # HTTPS
        if parsed.scheme == 'https':
            result['details']['safe_factors'].append('Uses HTTPS')
            result['confidence_score'] = max(0, result['confidence_score'] - 0.1)
        
        result['confidence_score'] = min(result['confidence_score'], 1.0)
        # A score of 0.5 represents multiple independent high-risk signals.
        result['is_phishing'] = result['confidence_score'] >= 0.5
        
        return result
