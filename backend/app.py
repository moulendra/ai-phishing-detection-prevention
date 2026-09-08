"""HTTP API for defensive phishing analysis."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

try:  # Supports both `python backend/app.py` and package imports in tests/WSGI.
    from .models.content_analyzer import ContentAnalyzer
    from .models.email_analyzer import EmailAnalyzer
    from .models.ml_classifier import MLClassifier
    from .models.url_analyzer import URLAnalyzer
except ImportError:  # pragma: no cover - direct-script compatibility
    from models.content_analyzer import ContentAnalyzer
    from models.email_analyzer import EmailAnalyzer
    from models.ml_classifier import MLClassifier
    from models.url_analyzer import URLAnalyzer

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)
MAX_INPUT_LENGTH = 20_000
load_dotenv()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).with_name("templates")))
    app.config.from_mapping(SECRET_KEY=os.getenv("SECRET_KEY") or None, SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///phishing_detection.db"), SQLALCHEMY_TRACK_MODIFICATIONS=False, STORE_ANALYSIS_CONTENT=os.getenv("STORE_ANALYSIS_CONTENT", "false").lower() == "true")
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"] and not app.config.get("TESTING"):
        raise RuntimeError("SECRET_KEY must be set outside test environments")
    CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "http://localhost:5000").split(",")}})
    db = SQLAlchemy(app)

    class DetectionResult(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        analysis_type = db.Column(db.String(20), nullable=False)
        input_data = db.Column(db.Text, nullable=False)
        is_phishing = db.Column(db.Boolean, nullable=False)
        confidence_score = db.Column(db.Float, nullable=False)
        risk_level = db.Column(db.String(10), nullable=False)
        detection_method = db.Column(db.String(30), nullable=False)
        timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
        details = db.Column(db.Text, nullable=False)

        def to_dict(self) -> dict:
            return {"id": self.id, "analysis_type": self.analysis_type, "input_data": self.input_data, "is_phishing": self.is_phishing, "confidence_score": self.confidence_score, "risk_level": self.risk_level, "detection_method": self.detection_method, "timestamp": self.timestamp.isoformat(), "details": json.loads(self.details)}

    url_analyzer, email_analyzer, content_analyzer, ml_classifier = URLAnalyzer(), EmailAnalyzer(), ContentAnalyzer(), MLClassifier()

    def risk_level(score: float) -> str:
        return "high" if score >= 0.70 else "medium" if score >= 0.40 else "low"

    def validate(field: str) -> str:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get(field), str) or not payload[field].strip():
            raise ValueError(f"'{field}' must be a non-empty string")
        if len(payload[field]) > MAX_INPUT_LENGTH:
            raise ValueError(f"'{field}' must not exceed {MAX_INPUT_LENGTH} characters")
        return payload[field].strip()

    def hybrid(rule_result: dict, ml_result: dict | None = None) -> dict:
        if not ml_result:
            return rule_result
        score = round(0.60 * rule_result["confidence_score"] + 0.40 * ml_result["confidence_score"], 4)
        return {"is_phishing": score >= 0.50, "confidence_score": score, "details": {**rule_result["details"], "ml": ml_result["details"], "rule_score": rule_result["confidence_score"], "ml_score": ml_result["confidence_score"]}}

    def record(kind: str, value: str, result: dict, method: str) -> None:
        stored = value[:500] if app.config["STORE_ANALYSIS_CONTENT"] else f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
        db.session.add(DetectionResult(analysis_type=kind, input_data=stored, is_phishing=result["is_phishing"], confidence_score=result["confidence_score"], risk_level=risk_level(result["confidence_score"]), detection_method=method, details=json.dumps(result["details"])))
        db.session.commit()

    def analyze(kind: str, field: str, rule: Callable[[str], dict], ml: Callable[[str], dict] | None = None):
        try:
            value = validate(field)
            result = hybrid(rule(value), ml(value) if ml else None)
            method = "hybrid" if ml else "rules"
            record(kind, value, result, method)
            return jsonify({**result, "risk_level": risk_level(result["confidence_score"]), "detection_method": method})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            db.session.rollback()
            logger.exception("Analysis failed for %s", kind)
            return jsonify({"error": "Analysis could not be completed"}), 500

    @app.get("/")
    def index(): return render_template("index.html")

    @app.post("/api/analyze/url")
    def analyze_url(): return analyze("url", "url", url_analyzer.analyze, ml_classifier.predict_url)

    @app.post("/api/analyze/email")
    def analyze_email(): return analyze("email", "email_content", email_analyzer.analyze, ml_classifier.predict_email)

    @app.post("/api/analyze/content")
    def analyze_content(): return analyze("content", "content", content_analyzer.analyze)

    @app.get("/api/stats")
    def stats():
        total = DetectionResult.query.count()
        phishing = DetectionResult.query.filter_by(is_phishing=True).count()
        return jsonify({"total_detections": total, "phishing_count": phishing, "legitimate_count": total - phishing, "detection_rate": round(100 * phishing / total, 2) if total else 0})

    @app.get("/api/reports")
    def reports():
        limit = min(max(request.args.get("limit", 10, type=int), 1), 100)
        rows = DetectionResult.query.order_by(DetectionResult.timestamp.desc()).limit(limit).all()
        return jsonify({"reports": [row.to_dict() for row in rows], "total": DetectionResult.query.count()})

    with app.app_context():
        db.create_all()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true", host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", "5000")))
