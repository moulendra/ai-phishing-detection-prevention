# System Architecture

## Overview

The AI Phishing Detection System uses a hybrid rule-based and machine learning approach to detect phishing threats.

## Components

```
┌─────────────┐
│   User      │
└──────┬──────┘
       │
       ├──────────┐
       │          │
┌──────▼──────┐ ┌▼──────────┐
│ Web UI      │ │ CLI Tool  │
└──────┬──────┘ └───────────┘
       │
┌──────▼──────────────────┐
│  Flask Application     │
│  (API Layer)           │
└──────┬──────────────────┘
       │
┌──────▼──────────────────┐
│  Detection Engine      │
│  ├─ URL Analyzer       │
│  ├─ Email Analyzer     │
│  └─ Content Analyzer   │
└──────┬──────────────────┘
       │
┌──────▼──────────────────┐
│  Database (SQLite)      │
└─────────────────────────┘
```

## Data Flow

1. User submits URL/email/content
2. Input validation
3. Rule-based analysis
4. Risk scoring
5. Result generation
6. Database logging
7. Response to user

## Security Architecture

- Input validation at API layer
- No direct URL fetching (SSRF protection)
- Safe error handling
- Database parameterization
- No sensitive data logging