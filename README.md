# AI-Based Phishing Detection & Prevention System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

An AI-powered phishing detection system combining rule-based analysis and machine learning to identify malicious URLs, emails, and web content.

## Features

- **URL Analysis**: Detects phishing URLs using rule-based pattern matching
- **Email Analysis**: Identifies phishing emails through content analysis
- **Content Analysis**: Scans web content for phishing indicators
- **Risk Scoring**: Provides confidence scores and risk levels
- **Web Interface**: Browser-based dashboard for analysis
- **CLI Tool**: Command-line interface for batch processing
- **Detection History**: Tracks all analyses in database

## Technology Stack

- **Backend**: Python, Flask
- **ML Framework**: scikit-learn
- **Database**: SQLite (via SQLAlchemy)
- **Frontend**: HTML, CSS, JavaScript

## Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-phishing-detection-prevention.git
cd ai-phishing-detection-prevention

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Web Interface

```bash
cd backend
python app.py
```

Access the dashboard at `http://localhost:5000`

### CLI Tool

```bash
# Analyze a URL
python backend/cli.py --url "http://example.com"

# Analyze email content
python backend/cli.py --email "Your email content here"

# Analyze web content
python backend/cli.py --content "<html>...</html>"
```

### API Endpoints

```bash
# Analyze URL
curl -X POST http://localhost:5000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com"}'

# Analyze email
curl -X POST http://localhost:5000/api/analyze/email \
  -H "Content-Type: application/json" \
  -d '{"email_content": "Your email here"}'

# Get statistics
curl http://localhost:5000/api/stats
```

## Detection Engine

The system uses a hybrid approach:

1. **Rule-Based Analysis**: Identifies known phishing patterns
2. **Feature Extraction**: Analyzes URL structure, email content, and web elements
3. **Risk Assessment**: Calculates confidence scores based on detected indicators

### URL Analysis Features

- Suspicious TLD detection (.xyz, .top, .tk, etc.)
- Keyword matching (login, verify, account, etc.)
- HTTPS detection
- URL structure analysis

### Email Analysis Features

- Urgency indicators detection
- Threat keyword identification
- Credential harvesting detection
- Social engineering pattern recognition

### Content Analysis Features

- Password field detection
- Form identification
- Suspicious keyword matching
- Credential harvesting indicators

## Security

This system is designed for defensive cybersecurity purposes. Key security features:

- Input validation and sanitization
- No direct URL fetching (SSRF protection)
- Safe error handling
- Database security
- Logging without sensitive data

## Limitations

- URL-only detection (does not visit sites)
- Rule-based system (may generate false positives)
- Machine learning component requires training data
- Not a replacement for comprehensive security solutions
- May not detect sophisticated zero-day attacks

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Security Reporting

For security issues, please follow the guidelines in [SECURITY.md](SECURITY.md).

## Disclaimer

This tool is for educational and defensive cybersecurity purposes only. The authors are not responsible for misuse.