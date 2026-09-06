"""
Content Analyzer - Rule-based phishing detection for web content
"""

from typing import Dict

class ContentAnalyzer:
    """Analyzes web content for phishing indicators"""
    
    def analyze(self, content: str, url: str = '') -> Dict:
        """Analyze web content for phishing indicators"""
        result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'details': {'indicators': [], 'risk_factors': [], 'safe_factors': []}
        }
        
        content_lower = content.lower()
        
        # Check for password fields
        if 'type="password"' in content_lower or 'password' in content_lower:
            result['details']['risk_factors'].append('Password field detected')
            result['confidence_score'] += 0.3
            result['details']['indicators'].append('password_fields')
        
        # Check for forms
        if '<form' in content_lower:
            result['details']['risk_factors'].append('Form detected')
            result['confidence_score'] += 0.2
            result['details']['indicators'].append('forms')
        
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'password', 'credit card', 'ssn', 'bank account']
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                result['details']['risk_factors'].append(f'Suspicious keyword: {keyword}')
                result['confidence_score'] += 0.15
                result['details']['indicators'].append('suspicious_keywords')
                break
        
        result['confidence_score'] = min(result['confidence_score'], 1.0)
        result['is_phishing'] = result['confidence_score'] > 0.5
        
        return result