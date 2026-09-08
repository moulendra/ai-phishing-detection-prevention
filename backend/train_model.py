"""Train and persist the URL/email models used by :mod:`backend.app`.

Input CSV files must contain `url,label` and `content,label` respectively,
where label is 0 (legitimate) or 1 (phishing). Sample data exists only to test
the pipeline; do not deploy a model trained from it.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from models.ml_classifier import MLClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler


def sample_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    urls = [("https://www.google.com", 0), ("https://docs.python.org", 0), ("https://github.com/openai", 0), ("https://www.wikipedia.org", 0), ("http://verify-account-login.xyz", 1), ("http://secure-paypal-login.top", 1), ("http://apple-id-verify.tk", 1), ("http://bank-account-confirm.zip", 1)]
    emails = [("Your order has shipped. Thank you for shopping with us.", 0), ("Team meeting moved to 10 AM tomorrow.", 0), ("Your monthly statement is ready for viewing.", 0), ("Welcome to the service.", 0), ("URGENT: verify your password now or your account will be closed.", 1), ("Security alert: confirm your login immediately to avoid suspension.", 1), ("Immediate action required: update account credentials.", 1), ("Your account is compromised. Verify identity now.", 1)]
    return pd.DataFrame(urls, columns=["url", "label"]), pd.DataFrame(emails, columns=["content", "label"])


def read_data(url_path: str | None, email_path: str | None, use_sample: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    if use_sample:
        return sample_data()
    if not url_path or not email_path:
        raise ValueError("Pass both --url-data and --email-data, or use --sample.")
    urls, emails = pd.read_csv(url_path), pd.read_csv(email_path)
    for data, columns in ((urls, {"url", "label"}), (emails, {"content", "label"})):
        if not columns.issubset(data.columns) or not set(data["label"].unique()).issubset({0, 1}):
            raise ValueError(f"Expected columns {sorted(columns)} with binary labels.")
    return urls, emails


def train(urls: pd.DataFrame, emails: pd.DataFrame) -> tuple[dict, str]:
    url_features = [MLClassifier.extract_url_features(url) for url in urls["url"]]
    scaler = StandardScaler().fit(url_features)
    url_model = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced").fit(scaler.transform(url_features), urls["label"])
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", min_df=1)
    email_features = vectorizer.fit_transform(emails["content"])
    email_model = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced").fit(email_features, emails["label"])
    report = classification_report(emails["label"], email_model.predict(email_features), zero_division=0)
    return {"url_model": url_model, "url_scaler": scaler, "email_model": email_model, "email_vectorizer": vectorizer}, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing-detection models from labelled CSVs.")
    parser.add_argument("--url-data", help="CSV containing url,label")
    parser.add_argument("--email-data", help="CSV containing content,label")
    parser.add_argument("--sample", action="store_true", help="Exercise the pipeline with tiny demonstration data")
    parser.add_argument("--output", default="backend/models/phishing_model.joblib")
    args = parser.parse_args()
    urls, emails = read_data(args.url_data, args.email_data, args.sample)
    models, report = train(urls, emails)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(models, output)
    print(f"Saved model bundle to {output}")
    print("Training-set email report (not a deployment metric):")
    print(report)


if __name__ == "__main__":
    main()
