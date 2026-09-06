# Data Directory

This directory is for storing training data and datasets.

## Dataset Requirements

For machine learning training, you will need:

- Labeled phishing URLs
- Labeled legitimate URLs
- Phishing email samples
- Legitimate email samples
- Phishing web content
- Legitimate web content

## Data Format

### URLs
- CSV format: `url,label`
- Labels: 0 (legitimate), 1 (phishing)

### Emails
- JSON format: `{"content": "...", "label": 0/1}`

### Content
- JSON format: `{"html": "...", "label": 0/1}`

## Data Sources

When collecting data, ensure:
- Proper attribution
- Legal compliance
- Privacy protection
- No personal information

## DO NOT COMMIT

Do not commit real datasets to this repository. Use sample data or instructions for obtaining datasets.