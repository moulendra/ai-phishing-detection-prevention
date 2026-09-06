"""
Email Analyzer - Rule-based phishing detection for emails
"""

import re
from typing import Dict

class EmailAnalyzer:
    """Analyzes email content for phishing indicators"""
    
    def __init__(self):
        self.urgency_keywords = ['urgent', 'immediate', 'action required', 'expire', 'deadline']
        self.threat_keywords = ['suspend', 'terminate', 'close', 'deactivate', 'compromised']
        self.credential_keywords = ['password', 'username', 'login', 'verify', 'confirm']
    
    def analyze(self, email_content: str, email_headers: Dict = None) -> Dict:
        """Analyze email content for phishing indicators"""
        result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'details': {'indicators': [], 'risk_factors': [], 'safe_factors': []}
        }
        
        content_lower = email_content.lower()
        
        # Check urgency
        urgency_count = sum(1 for keyword in self.urgency_keywords if keyword in content_lower)
        if urgency_count >= 2:
            result['details']['risk_factors'].append(f'Multiple urgency indicators: {urgency_count}')
            result['confidence_score'] += 0.3
            result['details']['indicators'].append('urgency')
        
        # Check threats
        threat_count = sum(1 for keyword in self.threat_keywords if keyword in content_lower)
        if threat_count >= 1:
            result['details']['risk_factors'].append(f'Threat indicators: {threat_count}')
            result['confidence_score'] += 0.25
            result['details']['indicators'].append('threats')
        
        # Check credentials
        credential_count = sum(1 for keyword in self.credential_keywords if keyword in content_lower)
        if credential_count >= 1:
            result['details']['risk_factors'].append(f'Credential indicators: {credential_count}')
            result['confidence_score'] += 0.3
            result['details']['indicators'].append('credentials')
        
        result['confidence_score'] = min(result['confidence_score'], 1.0)
        result['is_phishing'] = result['confidence_score'] > 0.5
        
        return result