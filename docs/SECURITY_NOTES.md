# Security Notes (OWASP-Oriented)

## Key Controls Implemented

- Input validation for domain and scan payloads
- API throttling by endpoint scope (`scan`, `telemetry`, `lookup`, `rescan`)
- Optional API token auth (`X-API-Token` / Bearer)
- Production-safe defaults in `config.settings.prod`
- Strict security headers (`X_FRAME_OPTIONS`, referrer policy, content sniffing protection)
- HTTPS + secure cookies enabled in production settings
- CORS lock-down support via env (`CORS_ALLOWED_ORIGINS`)
- CSRF trusted origin support for portal/admin workflows
- Extension CSP configured in manifest
- Extension token stored in local profile storage (not sync storage)
- SSRF hardening for HTTPS checks (block non-public IP targets)

## Operational Controls

- CI + security workflow
- Dependabot updates for pip/npm/docker/github-actions
- Scheduled stale-site rechecks via management command

## Required Deployment Hygiene

- Use `config.settings.prod` in production
- Set non-default `DJANGO_SECRET_KEY`
- Keep `CORS_ALLOW_ALL_ORIGINS=False` in production
- Use HTTPS endpoint for portal/extension API calls
- Rotate `API_AUTH_TOKEN` if used