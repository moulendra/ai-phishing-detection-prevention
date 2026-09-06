"""
ML Classifier - Machine learning based phishing detection
"""

import numpy as np
import re
from typing import Dict
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class MLClassifier:
    """Machine learning classifier for phishing detection"""
    
    def __init__(self):
        self.model_path = 'backend/models/phishing_model.pkl'
        self.url_model = None
        self.email_vectorizer = None
        self.scaler = None
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models with sample data"""
        try:
            if os.path.exists(self.model_path):
                logger.info("Loading existing ML models...")
                models = joblib.load(self.model_path)
                self.url_model = models.get('url_model')
                logger.info("Models loaded successfully")
            else:
                logger.info("No existing models, initializing...")
                self._train_basic_models()
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            self._train_basic_models()
    
    def _train_basic_models(self):
        """Train basic models with sample data"""
        # Sample training data
        url_samples = [
            ("https://www.google.com", 0),
            ("http://google-secure-login.com", 1),
            ("https://www.facebook.com", 0),
            ("http://apple-id-verify.xyz", 1),
        ]
        
        emails = [
            ("Thank you for your purchase. Order confirmed.", 0),
            ("URGENT: Your account will be closed unless you verify immediately.", 1),
        ]
        
        # Extract features for URLs
        url_features = []
        url_labels = []
        for url, label in url_samples:
            features = self._extract_url_features(url)
            url_features.append(features)
            url_labels.append(label)
        
        # Train URL model
        self.url_model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        self.scaler = StandardScaler()
        url_features_scaled = self.scaler.fit_transform(url_features)
        self.url_model.fit(url_features_scaled, url_labels)
        
        # Train email model
        self.email_vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        email_texts = [text for text, _ in emails]
        email_labels = [label for _, label in emails]
        email_features = self.email_vectorizer.fit_transform(email_texts)
        self.email_model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        self.email_model.fit(email_features, email_labels)
        
        logger.info("Basic model training complete")
    
    def _extract_url_features(self, url: str):
        """Extract features from URL"""
        features = [
            len(url),
            url.count('.'),
            url.count('-'),
            url.count('_'),
            url.count('='),
            1 if url.startswith('https') else 0,
            1 if any(tld in url for tld in ['.xyz', '.top', '.tk']) else 0,
            1 if 'login' in url.lower() else 0,
            1 if 'verify' in url.lower() else 0,
        ]
        return features
    
    def predict_url(self, url: str) -> Dict:
        """Predict if a URL is phishing"""
        result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'details': {'method': 'ml_random_forest', 'model_confidence': 0.0}
        }
        
        if not self.url_model:
            return result
        
        try:
            features = self._extract_url_features(url)
            features_scaled = self.scaler.transform([features])
            prediction = self.url_model.predict(features_scaled)[0]
            probabilities = self.url_model.predict_proba(features_scaled)[0]
            confidence = probabilities[1] if len(probabilities) > 1 else 0.0
            
            result['is_phishing'] = bool(prediction)
            result['confidence_score'] = float(confidence)
            result['details']['model_confidence'] = float(confidence)
            
        except Exception as e:
            logger.error(f"Error in URL prediction: {str(e)}")
        
        return result
    
    def predict_email(self, email_content: str) -> Dict:
        """Predict if an email is phishing"""
        result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'details': {'method': 'ml_random_forest', 'model_confidence': 0.0}
        }
        
        if not self.email_model or not self.email_vectorizer:
            return result
        
        try:
            features = self.email_vectorizer.transform([email_content])
            prediction = self.email_model.predict(features)[0]
            probabilities = self.email_model.predict_proba(features)[0]
            confidence = probabilities[1] if len(probabilities) > 1 else 0.0
            
            result['is_phishing'] = bool(prediction)
            result['confidence_score'] = float(confidence)
            result['details']['model_confidence'] = float(confidence)
            
        except Exception as e:
            logger.error(f"Error in email prediction: {str(e)}")
        
        return result