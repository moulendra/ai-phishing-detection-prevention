#!/usr/bin/env python3
"""
CLI Tool for AI Phishing Detection System
"""

import sys
import os
import argparse
from colorama import init, Fore, Style
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.url_analyzer import URLAnalyzer
from models.email_analyzer import EmailAnalyzer
from models.content_analyzer import ContentAnalyzer

init()

class PhishingDetectionCLI:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.email_analyzer = EmailAnalyzer()
        self.content_analyzer = ContentAnalyzer()
    
    def analyze_url(self, url):
        print(f"{Fore.CYAN}🔍 Analyzing URL: {url}{Style.RESET_ALL}")
        print("-" * 50)
        
        result = self.url_analyzer.analyze(url)
        
        status = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if result['is_phishing'] else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        print(f"Status: {status}")
        print(f"Confidence: {result['confidence_score']:.2%}")
        
        if result['details']['risk_factors']:
            print(f"\n{Fore.YELLOW}Risk Factors:{Style.RESET_ALL}")
            for factor in result['details']['risk_factors']:
                print(f"  - {factor}")
        
        if result['details']['safe_factors']:
            print(f"\n{Fore.GREEN}Safe Factors:{Style.RESET_ALL}")
            for factor in result['details']['safe_factors']:
                print(f"  - {factor}")
    
    def analyze_email(self, email_content):
        print(f"{Fore.CYAN}🔍 Analyzing Email{Style.RESET_ALL}")
        print("-" * 50)
        
        result = self.email_analyzer.analyze(email_content)
        
        status = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if result['is_phishing'] else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        print(f"Status: {status}")
        print(f"Confidence: {result['confidence_score']:.2%}")
        
        if result['details']['risk_factors']:
            print(f"\n{Fore.YELLOW}Risk Factors:{Style.RESET_ALL}")
            for factor in result['details']['risk_factors']:
                print(f"  - {factor}")
    
    def analyze_content(self, content):
        print(f"{Fore.CYAN}🔍 Analyzing Content{Style.RESET_ALL}")
        print("-" * 50)
        
        result = self.content_analyzer.analyze(content)
        
        status = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if result['is_phishing'] else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        print(f"Status: {status}")
        print(f"Confidence: {result['confidence_score']:.2%}")
        
        if result['details']['risk_factors']:
            print(f"\n{Fore.YELLOW}Risk Factors:{Style.RESET_ALL}")
            for factor in result['details']['risk_factors']:
                print(f"  - {factor}")

def main():
    parser = argparse.ArgumentParser(description='AI Phishing Detection System')
    parser.add_argument('--url', help='URL to analyze')
    parser.add_argument('--email', help='Email content to analyze')
    parser.add_argument('--content', help='Web content to analyze')
    
    args = parser.parse_args()
    
    if not any([args.url, args.email, args.content]):
        parser.print_help()
        return
    
    cli = PhishingDetectionCLI()
    
    if args.url:
        cli.analyze_url(args.url)
    elif args.email:
        cli.analyze_email(args.email)
    elif args.content:
        cli.analyze_content(args.content)

if __name__ == '__main__':
    main()