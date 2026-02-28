# Security Notes (OWASP-Oriented)

## Key Controls Implemented

- Strict input validation for domains and scan/auth payloads
- Scoped API throttling by endpoint (`scan`, `telemetry`, `lookup`, `rescan`, auth endpoints)
- Opaque hashed access/refresh token auth with rotation and revocation
- Session-backed device approval flow (`/auth/device/verify`)
- Optional static admin API token fallback (`API_AUTH_TOKEN`)
- Production-safe defaults in `config.settings.prod`
- Security headers:
  - `X_FRAME_OPTIONS=DENY`
  - `SECURE_CONTENT_TYPE_NOSNIFF=True`
  - `SECURE_REFERRER_POLICY=strict-origin-when-cross-origin`
- HTTPS redirect and secure cookies in production settings
- CORS/CSRF allowlists configured through environment variables
- Extension CSP set via MV3 manifest
- Extension stores summary cache only; detailed checks are fetched on demand
- SSRF hardening for outbound HTTPS checks (non-public IP targets blocked)

## Operational Controls

- CI + security workflows in GitHub Actions
- Dependabot updates for pip/npm/docker/github-actions
- CodeQL analysis workflow
- Scheduled stale-site rechecks via management command

## Required Deployment Hygiene

- Use `config.settings.prod`
- Set non-default `DJANGO_SECRET_KEY`
- Keep `CORS_ALLOW_ALL_ORIGINS=False`
- Set `API_REQUIRE_AUTH=True`
- Use HTTPS backend URL for extension
- Rotate/expire admin/static tokens if enabled
