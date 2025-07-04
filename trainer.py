#!/usr/bin/env python3
"""
URL Spam Detection Model Trainer

This script trains the RandomForest model for URL spam detection using advanced feature engineering
and real-world threat intelligence. It combines synthetic and realistic datasets for robust training.

Features:
- 22 advanced URL features including security indicators and phishing patterns
- Integration with real spam domains from threat intelligence
- Cross-validation and comprehensive evaluation
- Model persistence and performance analysis

Usage:
    python trainer.py
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
import urllib.parse
import re
import os
import logging
from typing import Tuple, List, Dict, Any
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class URLFeatureExtractor:
    """Extract features from URLs for spam detection."""
    
    def __init__(self):
        # Known spam domains from threat intelligence
        self.spam_domains = self._load_spam_domains()
        
        # Suspicious TLDs commonly used for spam
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download', '.stream',
            '.science', '.racing', '.party', '.review', '.trade', '.date',
            '.faith', '.bid', '.loan', '.cricket', '.win', '.accountant'
        }
        
        # Phishing keywords
        self.phishing_keywords = {
            'verify', 'suspended', 'update', 'confirm', 'account', 'security',
            'urgent', 'immediate', 'action', 'required', 'click', 'here',
            'login', 'signin', 'bank', 'paypal', 'amazon', 'microsoft',
            'google', 'apple', 'facebook', 'twitter', 'instagram'
        }
        
        # Security-related terms
        self.security_terms = {
            'ssl', 'secure', 'auth', 'token', 'session', 'credential',
            'password', 'pin', 'otp', 'verification', 'validate'
        }
    
    def _load_spam_domains(self) -> set:
        """Load known spam domains from various sources."""
        spam_domains = set()
        
        # Add some known spam domains (this would be loaded from threat intelligence feeds)
        default_spam_domains = {
            'bit.ly', 'tinyurl.com', 'ow.ly', 'is.gd', 't.co',  # URL shorteners often abused
            'accounts-google.com', 'paypal-verify.com', 'amazon-security.com',  # Typosquatting
            'microsoft-update.net', 'apple-verification.com', 'facebook-security.org'
        }
        
        spam_domains.update(default_spam_domains)
        return spam_domains
    
    def extract_features(self, url: str) -> List[float]:
        """Extract comprehensive features from a URL."""
        try:
            parsed = urllib.parse.urlparse(url.lower())
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = []
            
            # 1. URL Length
            features.append(len(url))
            
            # 2. Domain Length
            features.append(len(domain))
            
            # 3. Path Length
            features.append(len(path))
            
            # 4. Query Length
            features.append(len(query))
            
            # 5. Number of subdomains
            subdomains = domain.count('.')
            features.append(subdomains)
            
            # 6. Has HTTPS
            features.append(1 if parsed.scheme == 'https' else 0)
            
            # 7. Has IP address instead of domain
            ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
            has_ip = 1 if re.match(ip_pattern, domain.split(':')[0]) else 0
            features.append(has_ip)
            
            # 8. Suspicious TLD
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            has_suspicious_tld = 1 if tld in self.suspicious_tlds else 0
            features.append(has_suspicious_tld)
            
            # 9. Known spam domain
            is_spam_domain = 1 if domain in self.spam_domains else 0
            features.append(is_spam_domain)
            
            # 10. Number of dashes in domain
            features.append(domain.count('-'))
            
            # 11. Number of digits in domain
            features.append(sum(c.isdigit() for c in domain))
            
            # 12. Domain contains phishing keywords
            phishing_count = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
            features.append(phishing_count)
            
            # 13. URL contains security terms
            security_count = sum(1 for term in self.security_terms if term in url.lower())
            features.append(security_count)
            
            # 14. Has non-standard port
            port_match = re.search(r':(\d+)', domain)
            non_standard_port = 0
            if port_match:
                port = int(port_match.group(1))
                if port not in [80, 443, 8080, 8443]:
                    non_standard_port = 1
            features.append(non_standard_port)
            
            # 15. URL complexity (special characters)
            special_chars = sum(1 for c in url if c in '!@#$%^&*()+=[]{}|;:,.<>?')
            features.append(special_chars)
            
            # 16. Double slashes in path
            features.append(1 if '//' in path else 0)
            
            # 17. Typosquatting detection (common brand misspellings)
            typo_brands = ['gooogle', 'micr0soft', 'amaz0n', 'payp4l', 'faceb00k']
            has_typo = 1 if any(brand in url.lower() for brand in typo_brands) else 0
            features.append(has_typo)
            
            # 18. Domain appending (legitimate domain + suspicious extension)
            domain_append_pattern = r'(google|microsoft|amazon|paypal|facebook|apple|twitter)\.(com|net|org)\.[a-z]{2,}'
            has_domain_append = 1 if re.search(domain_append_pattern, url.lower()) else 0
            features.append(has_domain_append)
            
            # 19. Homograph attack detection (mixed scripts)
            has_mixed_script = 0
            try:
                # Check for non-ASCII characters that might be homographs
                if any(ord(c) > 127 for c in domain):
                    has_mixed_script = 1
            except:
                pass
            features.append(has_mixed_script)
            
            # 20. Number of parameters in query
            param_count = len(query.split('&')) if query else 0
            features.append(param_count)
            
            # 21. URL entropy (randomness measure)
            entropy = self._calculate_entropy(url)
            features.append(entropy)
            
            # 22. Brand impersonation score
            brand_score = self._calculate_brand_impersonation_score(url)
            features.append(brand_score)
            
            return features
            
        except Exception as e:
            logger.warning(f"Error extracting features from URL {url}: {e}")
            # Return default features in case of error
            return [0.0] * 22
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            prob = count / text_len
            if prob > 0:
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _calculate_brand_impersonation_score(self, url: str) -> float:
        """Calculate likelihood of brand impersonation."""
        legitimate_brands = ['google', 'microsoft', 'amazon', 'paypal', 'facebook', 'apple', 'twitter', 'instagram']
        score = 0.0
        
        url_lower = url.lower()
        for brand in legitimate_brands:
            if brand in url_lower:
                # Check if it's the actual domain or impersonation
                if f"{brand}.com" not in url_lower and f"www.{brand}.com" not in url_lower:
                    score += 1.0
        
        return score

class URLSpamTrainer:
    """Train URL spam detection model."""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.feature_names = [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'num_subdomains', 'has_https', 'has_ip', 'suspicious_tld',
            'known_spam_domain', 'domain_dashes', 'domain_digits',
            'phishing_keywords', 'security_terms', 'non_standard_port',
            'special_chars', 'double_slashes', 'typosquatting',
            'domain_appending', 'homograph_attack', 'query_params',
            'url_entropy', 'brand_impersonation'
        ]
    
    def load_and_prepare_data(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load and prepare training data."""
        logger.info(f"Loading data from {csv_path}")
        
        # Load dataset
        df = pd.read_csv(csv_path)
        logger.info(f"Loaded {len(df)} samples")
        
        # Extract features
        logger.info("Extracting features...")
        start_time = time.time()
        
        features = []
        for i, url in enumerate(df['url']):
            if i % 1000 == 0:
                logger.info(f"Processed {i}/{len(df)} URLs")
            
            url_features = self.feature_extractor.extract_features(url)
            features.append(url_features)
        
        X = np.array(features)
        y = df['label'].values
        
        logger.info(f"Feature extraction completed in {time.time() - start_time:.2f} seconds")
        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info(f"Label distribution: {np.bincount(y)}")
        
        return X, y
    
    def train_model(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train the RandomForest model."""
        logger.info("Training RandomForest model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        # Predictions for detailed metrics
        y_pred = self.model.predict(X_test)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5, scoring='accuracy')
        
        # Feature importance
        feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
        
        results = {
            'train_accuracy': train_score,
            'test_accuracy': test_score,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'feature_importance': feature_importance,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        logger.info(f"Training completed!")
        logger.info(f"Train Accuracy: {train_score:.4f}")
        logger.info(f"Test Accuracy: {test_score:.4f}")
        logger.info(f"CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        logger.info(f"Precision: {results['precision']:.4f}")
        logger.info(f"Recall: {results['recall']:.4f}")
        logger.info(f"F1-Score: {results['f1_score']:.4f}")
        
        return results
    
    def save_model(self, model_path: str = 'url_spam_model'):
        """Save the trained model."""
        if self.model is None:
            raise ValueError("No model to save. Train a model first.")
        
        # Create directory if it doesn't exist
        os.makedirs(model_path, exist_ok=True)
        
        # Save model
        model_file = os.path.join(model_path, 'url_spam_classifier.pkl')
        joblib.dump(self.model, model_file)
        
        logger.info(f"Model saved to {model_file}")
    
    def analyze_feature_importance(self) -> None:
        """Analyze and display feature importance."""
        if self.model is None:
            raise ValueError("No model available. Train a model first.")
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        logger.info("\nTop 10 Most Important Features:")
        logger.info("=" * 40)
        for idx, row in importance_df.head(10).iterrows():
            logger.info(f"{row['feature']:<20}: {row['importance']:.4f}")

def main():
    """Main training function."""
    logger.info("Starting URL Spam Detection Model Training")
    
    # Initialize trainer
    trainer = URLSpamTrainer()
    
    # Load and prepare data
    dataset_path = 'link_spam_dataset.csv'
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found: {dataset_path}")
        logger.info("Please ensure the dataset file exists before training.")
        return
    
    X, y = trainer.load_and_prepare_data(dataset_path)
    
    # Train model
    results = trainer.train_model(X, y)
    
    # Save model
    trainer.save_model()
    
    # Analyze features
    trainer.analyze_feature_importance()
    
    logger.info("Training completed successfully!")
    logger.info(f"Model saved to: url_spam_model/url_spam_classifier.pkl")

if __name__ == '__main__':
    main()


