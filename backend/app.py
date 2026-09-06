"""
Flask Web Application for Phishing Detection System
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import os
import sys
import logging
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.url_analyzer import URLAnalyzer
from models.email_analyzer import EmailAnalyzer
from models.content_analyzer import ContentAnalyzer

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()
content_analyzer = ContentAnalyzer()

class DetectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analysis_type = db.Column(db.String(50), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    detection_method = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'analysis_type': self.analysis_type,
            'input_data': self.input_data,
            'is_phishing': self.is_phishing,
            'confidence_score': self.confidence_score,
            'risk_level': self.risk_level,
            'detection_method': self.detection_method,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        result = url_analyzer.analyze(url)
        
        detection = DetectionResult(
            analysis_type='url',
            input_data=url,
            is_phishing=result['is_phishing'],
            confidence_score=result['confidence_score'],
            risk_level='high' if result['confidence_score'] > 0.7 else 'medium' if result['confidence_score'] > 0.4 else 'low',
            detection_method='rules',
            details=str(result['details'])
        )
        db.session.add(detection)
        db.session.commit()
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    try:
        data = request.get_json()
        email_content = data.get('email_content')
        
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400
        
        result = email_analyzer.analyze(email_content)
        
        detection = DetectionResult(
            analysis_type='email',
            input_data=email_content[:500],
            is_phishing=result['is_phishing'],
            confidence_score=result['confidence_score'],
            risk_level='high' if result['confidence_score'] > 0.7 else 'medium' if result['confidence_score'] > 0.4 else 'low',
            detection_method='rules',
            details=str(result['details'])
        )
        db.session.add(detection)
        db.session.commit()
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        total = DetectionResult.query.count()
        phishing = DetectionResult.query.filter_by(is_phishing=True).count()
        
        return jsonify({
            'total_detections': total,
            'phishing_count': phishing,
            'legitimate_count': total - phishing,
            'detection_rate': round((phishing / total * 100) if total > 0 else 0, 2)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)