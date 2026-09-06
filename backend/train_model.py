#!/usr/bin/env python3
"""
Training Script for ML Models
Train and evaluate machine learning models for phishing detection
"""

import sys
import os
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.ml_classifier import MLClassifier

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModelTrainer:
    """Train and evaluate ML models for phishing detection"""
    
    def __init__(self, data_dir='data/training'):
        self.data_dir = Path(data_dir)
        self.model_dir = Path('backend/models')
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize classifier
        self.classifier = MLClassifier()
    
    def generate_sample_data(self):
        """Generate sample training data for demonstration"""
        logger.info("Generating sample training data...")
        
        # Sample URLs
        urls = {
            'legitimate': [
                'https://www.google.com',
                'https://www.facebook.com',
                'https://www.amazon.com',
                'https://www.apple.com',
                'https://www.microsoft.com',
                'https://www.paypal.com',
                'https://www.ebay.com',
                'https://www.netflix.com',
                'https://github.com',
                'https://stackoverflow.com',
                'https://www.linkedin.com',
                'https://www.twitter.com',
                'https://www.reddit.com',
                'https://www.wikipedia.org',
                'https://www.youtube.com'
            ],
            'phishing': [
                'http://google-secure-login.com',
                'http://facebook-verify-account.xyz',
                'http://amazon-update-info.top',
                'http://apple-id-confirm.tk',
                'http://microsoft-account-secure.ml',
                'http://paypal-login-verify.ga',
                'http://ebay-account-update.cf',
                'http://netflix-payment-confirm.zip',
                'http://secure-bank-login.com',
                'http://verify-account-info.com',
                'http://apple-id-verify.xyz',
                'http://google-account-recovery.top',
                'http://facebook-password-reset.tk',
                'http://amazon-payment-verify.ml',
                'http://microsoft-secure-login.ga'
            ]
        }
        
        # Sample emails
        emails = {
            'legitimate': [
                'Thank you for your recent purchase. Your order has been confirmed and will be shipped within 2-3 business days.',
                'Meeting reminder: Project team sync tomorrow at 10 AM in conference room A.',
                'Your monthly statement is now available for viewing. Please log in to your account to see details.',
                'Welcome to our service! Your account has been successfully created.',
                'Password reset request received. If you did not make this request, please ignore this email.',
                'Your subscription has been renewed successfully. Thank you for your continued support.',
                'New login detected from your device. If this was you, no action is needed.',
                'Your invoice for last month is ready. Payment is due by the end of the month.',
                'We have updated our privacy policy. Please review the changes at your convenience.',
                'Thank you for contacting support. Your ticket has been received and will be processed shortly.'
            ],
            'phishing': [
                'URGENT: Your account will be closed unless you verify your information immediately. Click here now.',
                'Security Alert: Unusual activity detected on your account. Verify your identity or lose access.',
                'Your password has been compromised. Reset immediately using this secure link.',
                'Dear Customer, Your Apple ID has been locked for security reasons. Verify now to restore access.',
                'FINAL NOTICE: Your Microsoft account will be terminated. Click to prevent account closure.',
                'Your PayPal account has been limited. Update your information to restore full access.',
                'Bank Alert: Unusual login attempt detected. Confirm your identity or your account will be blocked.',
                'URGENT: Payment required immediately or your service will be disconnected. Act now.',
                'Your Netflix subscription has expired. Update payment information to continue watching.',
                'Verify your Amazon account information or lose access to your order history and payment methods.'
            ]
        }
        
        # Sample web content
        content = {
            'legitimate': [
                '<html><body><h1>Welcome to Our Website</h1><p>This is a legitimate webpage with normal content.</p></body></html>',
                '<div class="product"><h2>Product Description</h2><p>Learn more about our amazing products.</p></div>',
                '<html><head><title>Contact Us</title></head><body><h1>Contact Information</h1><p>Email us at info@example.com</p></body></html>',
                '<div class="about"><h2>About Us</h2><p>We are a company dedicated to providing quality service.</p></div>',
                '<html><body><h1>Terms of Service</h1><p>Read our terms and conditions here.</p></body></html>'
            ],
            'phishing': [
                '<form><input type="password" name="password"><input type="submit" value="Login to Secure Account"></form>',
                '<form action="http://fake-site.com/collect"><input type="password" name="pass"><input type="text" name="credit_card"></form>',
                '<h1>Security Alert</h1><p>Verify your account immediately</p><form><input type="password" name="login"></form>',
                '<form><input type="password" name="password"><input type="password" name="confirm_password">Confirm credentials</form>',
                '<iframe src="http://malicious-site.com"></iframe><form><input type="password" name="user_pass"></form>'
            ]
        }
        
        # Create DataFrames
        url_data = []
        for url in urls['legitimate']:
            url_data.append({'url': url, 'label': 0})
        for url in urls['phishing']:
            url_data.append({'url': url, 'label': 1})
        
        email_data = []
        for email in emails['legitimate']:
            email_data.append({'content': email, 'label': 0})
        for email in emails['phishing']:
            email_data.append({'content': email, 'label': 1})
        
        content_data = []
        for cont in content['legitimate']:
            content_data.append({'content': cont, 'label': 0})
        for cont in content['phishing']:
            content_data.append({'content': cont, 'label': 1})
        
        return {
            'urls': pd.DataFrame(url_data),
            'emails': pd.DataFrame(email_data),
            'content': pd.DataFrame(content_data)
        }
    
    def train_url_model(self, data):
        """Train URL classification model"""
        logger.info("Training URL classification model...")
        
        # Extract features
        features = self.classifier._extract_url_features(data['url'].tolist())
        labels = data['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train model
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"URL Model Accuracy: {accuracy:.2%}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        return model, accuracy
    
    def train_email_model(self, data):
        """Train email classification model"""
        logger.info("Training email classification model...")
        
        # Vectorize content
        vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 2),
            lowercase=True,
            stop_words='english'
        )
        
        features = vectorizer.fit_transform(data['content'].tolist())
        labels = data['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train model
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Email Model Accuracy: {accuracy:.2%}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        return model, vectorizer, accuracy
    
    def train_content_model(self, data):
        """Train content classification model"""
        logger.info("Training content classification model...")
        
        # Vectorize content
        vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),
            lowercase=True,
            stop_words='english'
        )
        
        features = vectorizer.fit_transform(data['content'].tolist())
        labels = data['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train model
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Content Model Accuracy: {accuracy:.2%}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        return model, vectorizer, accuracy
    
    def train_all_models(self):
        """Train all models"""
        logger.info("Starting model training process...")
        
        # Generate sample data
        data = self.generate_sample_data()
        
        # Train individual models
        url_model, url_accuracy = self.train_url_model(data['urls'])
        email_model, email_vectorizer, email_accuracy = self.train_email_model(data['emails'])
        content_model, content_vectorizer, content_accuracy = self.train_content_model(data['content'])
        
        # Update classifier with trained models
        self.classifier.url_model = url_model
        self.classifier.email_model = email_model
        self.classifier.content_model = content_model
        self.classifier.url_vectorizer = None  # URL uses custom feature extraction
        self.classifier.email_vectorizer = email_vectorizer
        self.classifier.content_vectorizer = content_vectorizer
        
        # Save models
        self.classifier.save_models()
        
        # Print summary
        logger.info("\n" + "="*50)
        logger.info("TRAINING SUMMARY")
        logger.info("="*50)
        logger.info(f"URL Model Accuracy: {url_accuracy:.2%}")
        logger.info(f"Email Model Accuracy: {email_accuracy:.2%}")
        logger.info(f"Content Model Accuracy: {content_accuracy:.2%}")
        logger.info(f"Overall Average Accuracy: {(url_accuracy + email_accuracy + content_accuracy) / 3:.2%}")
        logger.info("="*50)
        
        logger.info("Models saved successfully to backend/models/")

def main():
    parser = argparse.ArgumentParser(description='Train ML models for phishing detection')
    parser.add_argument('--data', default='data/training', help='Directory containing training data')
    parser.add_argument('--sample', action='store_true', help='Generate and use sample data')
    
    args = parser.parse_args()
    
    trainer = ModelTrainer(args.data)
    
    if args.sample:
        logger.info("Using sample data for training...")
    else:
        logger.info(f"Looking for training data in {args.data}...")
        # Add logic to load real data if available
    
    trainer.train_all_models()

if __name__ == '__main__':
    main()