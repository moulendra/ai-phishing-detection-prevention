# Detection Engine Documentation

## URL Analysis

### Process

1. **Input Validation**: Basic URL format checking
2. **TLD Analysis**: Check against suspicious TLD list
3. **Keyword Matching**: Search for phishing-related keywords
4. **Security Check**: HTTPS verification
5. **Risk Scoring**: Calculate confidence score

### Features

- **Length**: URL length analysis
- **Special Characters**: Count of dots, hyphens, underscores
- **Protocol**: HTTP vs HTTPS
- **TLD**: Top-level domain reputation
- **Keywords**: Suspicious word detection

## Email Analysis

### Process

1. **Content Analysis**: Text pattern matching
2. **Urgency Detection**: Time-sensitive language
3. **Threat Detection**: Account closure/suspension language
4. **Credential Detection**: Password/account request patterns
5. **Risk Scoring**: Calculate confidence score

### Features

- **Urgency Keywords**: immediate, urgent, deadline
- **Threat Keywords**: suspend, terminate, close
- **Credential Keywords**: password, login, verify

## Content Analysis

### Process

1. **HTML Parsing**: Structure analysis
2. **Form Detection**: Input field identification
3. **Password Field Detection**: Credential harvesting indicators
4. **Keyword Matching**: Suspicious content patterns
5. **Risk Scoring**: Calculate confidence score

### Features

- **Forms**: Form element detection
- **Password Fields**: Input type="password"
- **Keywords**: login, credit card, ssn

## Risk Scoring

- **Low (0-0.4)**: Safe, minimal indicators
- **Medium (0.4-0.7)**: Suspicious, review recommended
- **High (0.7-1.0)**: Likely phishing, avoid interaction