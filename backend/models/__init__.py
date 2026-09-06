"""
Models package for phishing detection
"""

from .url_analyzer import URLAnalyzer
from .email_analyzer import EmailAnalyzer
from .content_analyzer import ContentAnalyzer

__all__ = ['URLAnalyzer', 'EmailAnalyzer', 'ContentAnalyzer']