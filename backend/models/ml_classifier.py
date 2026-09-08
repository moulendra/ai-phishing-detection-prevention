"""Reproducible baseline ML models used by the hybrid detection service.

Bundled samples make the app runnable for demonstrations only. They are not a
production-trained model; deployers should load a versioned model trained on
representative data.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class MLClassifier:
    """Provides URL and email baseline probabilities for hybrid scoring."""

    def __init__(self, model_path: str | None = None) -> None:
        self.model_path = Path(model_path or os.getenv("MODEL_PATH", "backend/models/phishing_model.joblib"))
        self.url_model = self.url_scaler = self.email_model = self.email_vectorizer = None
        self.model_source = "bundled demonstration baseline"
        self._load_or_train()

    @staticmethod
    def extract_url_features(url: str) -> list[float]:
        value = url.lower()
        return [len(value), value.count("."), value.count("-"), value.count("_"), value.count("="), float(value.startswith("https://")), float(any(tld in value for tld in (".xyz", ".top", ".tk", ".zip"))), float(any(word in value for word in ("login", "verify", "secure", "account")))]

    def _load_or_train(self) -> None:
        if self.model_path.exists():
            try:
                models: dict[str, Any] = joblib.load(self.model_path)
                self.url_model, self.url_scaler = models["url_model"], models["url_scaler"]
                self.email_model, self.email_vectorizer = models["email_model"], models["email_vectorizer"]
                self.model_source = "local trained model"
                return
            except (OSError, KeyError, ValueError) as exc:
                logger.warning("Could not load model %s: %s", self.model_path, exc)
        self._train_demo_baseline()

    def _train_demo_baseline(self) -> None:
        urls = [("https://www.google.com", 0), ("https://docs.python.org", 0), ("https://github.com/openai", 0), ("http://verify-account-login.xyz", 1), ("http://secure-paypal-login.top", 1), ("http://apple-id-verify.tk", 1)]
        emails = [("Your order has shipped. Thank you for shopping with us.", 0), ("Team meeting moved to 10 AM tomorrow.", 0), ("URGENT: verify your password now or your account will be closed.", 1), ("Security alert: confirm your login immediately to avoid suspension.", 1)]
        self.url_scaler = StandardScaler().fit([self.extract_url_features(url) for url, _ in urls])
        self.url_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
        self.url_model.fit(self.url_scaler.transform([self.extract_url_features(url) for url, _ in urls]), [label for _, label in urls])
        self.email_vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        matrix = self.email_vectorizer.fit_transform([text for text, _ in emails])
        self.email_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
        self.email_model.fit(matrix, [label for _, label in emails])

    @staticmethod
    def _prediction(model: Any, features: Any) -> float:
        classes = list(model.classes_)
        return float(model.predict_proba(features)[0][classes.index(1)]) if 1 in classes else 0.0

    def predict_url(self, url: str) -> dict[str, Any]:
        probability = self._prediction(self.url_model, self.url_scaler.transform([self.extract_url_features(url)]))
        return {"is_phishing": probability >= 0.5, "confidence_score": probability, "details": {"method": "random_forest", "model_source": self.model_source}}

    def predict_email(self, content: str) -> dict[str, Any]:
        probability = self._prediction(self.email_model, self.email_vectorizer.transform([content]))
        return {"is_phishing": probability >= 0.5, "confidence_score": probability, "details": {"method": "random_forest", "model_source": self.model_source}}
