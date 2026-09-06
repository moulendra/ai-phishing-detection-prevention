"""
Basic tests for the phishing detection system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.url_analyzer import URLAnalyzer
from backend.models.email_analyzer import EmailAnalyzer
from backend.models.content_analyzer import ContentAnalyzer

def test_url_analyzer():
    """Test URL analyzer"""
    analyzer = URLAnalyzer()
    
    legitimate = analyzer.analyze("https://www.google.com")
    phishing = analyzer.analyze("http://apple-id-verify.xyz")
    
    return phishing['confidence_score'] > legitimate['confidence_score']

def test_email_analyzer():
    """Test email analyzer"""
    analyzer = EmailAnalyzer()
    
    legitimate = analyzer.analyze("Thank you for your purchase.")
    phishing = analyzer.analyze("URGENT: Your account will be closed unless you verify immediately.")
    
    return not legitimate['is_phishing'] and phishing['is_phishing']

def test_content_analyzer():
    """Test content analyzer"""
    analyzer = ContentAnalyzer()
    
    legitimate = analyzer.analyze("<html><body><h1>Welcome</h1></body></html>")
    phishing = analyzer.analyze("<form><input type='password'></form>")
    
    return phishing['confidence_score'] > legitimate['confidence_score']

def run_all_tests():
    """Run all tests"""
    print("Running tests...")
    
    url_test = test_url_analyzer()
    email_test = test_email_analyzer()
    content_test = test_content_analyzer()
    
    print(f"URL: {'PASS' if url_test else 'FAIL'}")
    print(f"Email: {'PASS' if email_test else 'FAIL'}")
    print(f"Content: {'PASS' if content_test else 'FAIL'}")
    
    return url_test and email_test and content_test

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)