#!/usr/bin/env python3
"""
Production URL Spam/Phishing Detector

A production-ready module for detecting spam and phishing URLs using a trained
machine learning model with real-world threat intelligence.

Author: Enhanced Spam Detection System
Date: July 2025
Version: 1.0.0
"""

import joblib
import pandas as pd
import re
import numpy as np
from urllib.parse import urlparse
from typing import Dict, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLSpamDetector:
    """
    Production-ready URL spam and phishing detector.
    
    This class loads a pre-trained machine learning model and provides
    methods to analyze URLs for spam and phishing characteristics.
    """
    
    def __init__(self, model_path: str = "url_spam_model/url_spam_classifier.pkl"):
        """
        Initialize the URL spam detector.
        
        Args:
            model_path (str): Path to the trained model file
        """
        self.model = None
        self.model_path = model_path
        self.phishing_keywords = {
            'login', 'signin', 'secure', 'verify', 'account', 'update',
            'confirm', 'activate', 'unlock', 'billing', 'payment',
            'security', 'suspended', 'limited', 'expired', 'urgently'
        }
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.vu', '.cd', '.sy', '.nr'
        }
        self.load_model()
    
    def load_model(self) -> None:
        """Load the trained model from disk."""
        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Model loaded successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model from {self.model_path}: {e}")
            raise
    
    def extract_features(self, url: str) -> Dict[str, float]:
        """
        Extract features from a URL for spam detection.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict[str, float]: Dictionary of extracted features
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            
            # Basic URL components
            features = {
                'url_length': len(url),
                'hostname_length': len(hostname) if hostname else 0,
                'path_length': len(parsed.path),
                'query_length': len(parsed.query) if parsed.query else 0,
            }
            
            # Character analysis
            features.update({
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'digit_count': sum(c.isdigit() for c in url),
                'special_char_count': sum(not c.isalnum() and c not in '.-_/' for c in url),
            })
            
            # Security indicators
            features.update({
                'has_ip_address': bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname or '')),
                'uses_https': parsed.scheme == 'https',
                'has_port': bool(parsed.port),
                'has_at_symbol': '@' in url,
                'has_credentials': bool(parsed.username or parsed.password),
            })
            
            # Domain analysis
            if hostname:
                domain_parts = hostname.split('.')
                features['num_subdomains'] = max(0, len(domain_parts) - 2)
                features['excessive_subdomains'] = len(domain_parts) > 4
            else:
                features['num_subdomains'] = 0
                features['excessive_subdomains'] = False
            
            # Phishing indicators
            url_lower = url.lower()
            features.update({
                'has_phishing_keyword': any(keyword in url_lower for keyword in self.phishing_keywords),
                'has_suspicious_tld': any(tld in url_lower for tld in self.suspicious_tlds),
                'has_typosquatting': self._detect_typosquatting(hostname or ''),
                'multiple_security_keywords': sum(keyword in url_lower for keyword in ['secure', 'login', 'verify', 'account']) > 1,
            })
            
            # Advanced patterns
            features.update({
                'has_long_random_token': bool(re.search(r'[a-zA-Z0-9]{20,}', url)),
                'is_tunneling_service': 'ngrok' in url_lower or 'localtunnel' in url_lower,
                'url_complexity': self._calculate_complexity(url),
            })
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from URL '{url}': {e}")
            # Return default features if extraction fails
            return {key: 0.0 for key in self._get_feature_names()}
    
    def _detect_typosquatting(self, hostname: str) -> bool:
        """Detect potential typosquatting in hostname."""
        if not hostname:
            return False
            
        suspicious_patterns = [
            r'\d+[a-z]+\.com',  # Numbers mixed with letters
            r'[a-z]+(0|1|3|5|7)+[a-z]*\.com',  # Common character substitutions
            r'g[o0]{2,}gle',  # Google typos
            r'micr[o0]s[o0]ft',  # Microsoft typos
            r'[a-z]*app?le[a-z]*',  # Apple typos
        ]
        
        return any(re.search(pattern, hostname.lower()) for pattern in suspicious_patterns)
    
    def _calculate_complexity(self, url: str) -> float:
        """Calculate URL complexity score."""
        if not url:
            return 0.0
            
        factors = [
            len(re.findall(r'[^a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]', url)) / len(url),
            url.count('/') / len(url),
            url.count('?') + url.count('&'),
            len(url) / 100,  # Length factor
        ]
        
        return sum(factors) / len(factors)
    
    def _get_feature_names(self) -> list:
        """Get list of feature names in the correct order."""
        return [
            'url_length', 'hostname_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'has_ip_address', 'uses_https',
            'num_subdomains', 'has_at_symbol', 'has_phishing_keyword',
            'digit_count', 'special_char_count', 'has_suspicious_tld',
            'has_typosquatting', 'excessive_subdomains', 'has_long_random_token',
            'has_port', 'is_tunneling_service', 'multiple_security_keywords',
            'has_credentials', 'url_complexity'
        ]
    
    def predict(self, url: str) -> Tuple[bool, float, Dict]:
        """
        Predict if a URL is spam/phishing.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Tuple[bool, float, Dict]: (is_spam, confidence, details)
                - is_spam: True if URL is classified as spam/phishing
                - confidence: Confidence score (0-1)
                - details: Additional information about the prediction
        """
        if not self.model:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        try:
            # Extract features
            features = self.extract_features(url)
            feature_names = self._get_feature_names()
            
            # Create DataFrame with correct feature order
            features_df = pd.DataFrame([features])
            features_df = features_df.reindex(columns=feature_names, fill_value=0)
            
            # Make prediction
            prediction = self.model.predict(features_df)[0]
            probabilities = self.model.predict_proba(features_df)[0]
            confidence = float(max(probabilities))
            
            # Prepare details
            details = {
                'url': url,
                'classification': 'spam' if prediction == 1 else 'legitimate',
                'confidence': confidence,
                'risk_factors': self._identify_risk_factors(features),
                'features': features
            }
            
            return bool(prediction), confidence, details
            
        except Exception as e:
            logger.error(f"Error predicting URL '{url}': {e}")
            return False, 0.0, {'error': str(e)}
    
    def _identify_risk_factors(self, features: Dict[str, float]) -> list:
        """Identify key risk factors in the URL."""
        risk_factors = []
        
        if features.get('has_phishing_keyword', 0):
            risk_factors.append("Contains phishing keywords")
        if features.get('has_suspicious_tld', 0):
            risk_factors.append("Uses suspicious top-level domain")
        if features.get('has_typosquatting', 0):
            risk_factors.append("Possible typosquatting detected")
        if features.get('has_ip_address', 0):
            risk_factors.append("Uses IP address instead of domain")
        if not features.get('uses_https', 0):
            risk_factors.append("Does not use HTTPS")
        if features.get('excessive_subdomains', 0):
            risk_factors.append("Excessive number of subdomains")
        if features.get('has_long_random_token', 0):
            risk_factors.append("Contains long random tokens")
        if features.get('multiple_security_keywords', 0):
            risk_factors.append("Multiple security-related keywords")
        if features.get('url_complexity', 0) > 0.3:
            risk_factors.append("High URL complexity")
        
        return risk_factors
    
    def batch_predict(self, urls: list) -> list:
        """
        Predict multiple URLs in batch.
        
        Args:
            urls (list): List of URLs to analyze
            
        Returns:
            list: List of prediction results
        """
        results = []
        for url in urls:
            try:
                is_spam, confidence, details = self.predict(url)
                results.append(details)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'classification': 'error',
                    'confidence': 0.0
                })
        return results


def main():
    """Demo function showing how to use the URL spam detector."""
    detector = URLSpamDetector()
    
    # Test URLs
    test_urls = [
        "https://github.com/user/repo",
        "https://accounts.google.com/signin",
        "http://guerrillamail.com/login",
        "https://secure-paypal.fake-domain.com/login",
        "http://g00gle.com/signin",
        "https://stackoverflow.com/questions/12345"
    ]
    
    print("URL Spam Detection Results:")
    print("=" * 60)
    
    for url in test_urls:
        is_spam, confidence, details = detector.predict(url)
        status = "🚨 SPAM" if is_spam else "✅ SAFE"
        print(f"\n{status} | Confidence: {confidence:.1%}")
        print(f"URL: {url}")
        if details.get('risk_factors'):
            print(f"Risk Factors: {', '.join(details['risk_factors'])}")


if __name__ == "__main__":
    main()
