# Security Policy

## Supported Versions

- Version 1.0.0 (current)

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** create a public issue
2. Send an email with details to the project maintainers via GitHub Security Advisory
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

## Security Features

This project implements several security measures:

- Input validation and sanitization
- SSRF protection (no direct URL fetching)
- Safe error handling
- Database parameterization
- No logging of sensitive data
- Debug mode disabled by default (controlled via FLASK_DEBUG environment variable)
- Host binding defaults to 127.0.0.1 (controlled via FLASK_HOST environment variable)

## Security Limitations

- SQLite database (not production-ready for high-security environments)
- Flask development server (use WSGI in production)
- No authentication/authorization (add for production)
- No rate limiting (add for production)

## Best Practices

- Use environment variables for sensitive configuration
- Keep dependencies updated
- Use production WSGI server (Gunicorn, uWSGI)
- Implement authentication for API endpoints
- Add rate limiting
- Use HTTPS in production
- Regular security audits

## Environment Variables

- `FLASK_DEBUG`: Set to `true` only for development (default: `False`)
- `FLASK_HOST`: Set to `0.0.0.0` for production with proper network controls (default: `127.0.0.1`)
- `FLASK_PORT`: Port to bind to (default: `5000`)
- `SECRET_KEY`: Flask secret key (required for production)