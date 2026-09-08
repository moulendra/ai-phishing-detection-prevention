"""Unit and API-contract tests for the defensive analysis service."""
import os
import sys
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-not-for-production")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import create_app
from backend.models.content_analyzer import ContentAnalyzer
from backend.models.email_analyzer import EmailAnalyzer
from backend.models.url_analyzer import URLAnalyzer


def test_rule_analyzers_flag_clear_signals():
    assert URLAnalyzer().analyze("http://apple-id-verify.xyz")["is_phishing"]
    assert EmailAnalyzer().analyze("URGENT: verify your password or your account will be closed")["is_phishing"]
    assert ContentAnalyzer().analyze('<form><input type="password"></form>')["is_phishing"]


def test_url_endpoint_returns_hybrid_result_and_redacts_submission(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db"})
    response = app.test_client().post("/api/analyze/url", json={"url": "http://verify-account-login.xyz"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["detection_method"] == "hybrid"
    assert body["is_phishing"] is True
    reports = app.test_client().get("/api/reports").get_json()["reports"]
    assert reports[0]["input_data"].startswith("sha256:")


def test_api_rejects_missing_or_oversized_input(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db"})
    client = app.test_client()
    assert client.post("/api/analyze/email", json={}).status_code == 400
    assert client.post("/api/analyze/content", json={"content": "x" * 20_001}).status_code == 400
