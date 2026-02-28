# Release Checklist

## Backend

- [ ] `DEBUG=False`
- [ ] `DJANGO_SETTINGS_MODULE=config.settings.prod`
- [ ] Strong `DJANGO_SECRET_KEY`
- [ ] `ALLOWED_HOSTS` locked to production hosts
- [ ] `CORS_ALLOW_ALL_ORIGINS=False`
- [ ] `CORS_ALLOWED_ORIGINS` includes extension origin only
- [ ] `CSRF_TRUSTED_ORIGINS` configured
- [ ] `DATABASE_URL` points to Supabase Postgres
- [ ] `API_REQUIRE_AUTH=True`
- [ ] `GET /api/health` verified in production
- [ ] Admin user exists for extension approvals

## Risk Engine Operations

- [ ] Recheck cron configured: `python manage.py recheck_sites --days 7 --limit 500`
- [ ] Logs monitored for WHOIS/DNS/network failure spikes

## Extension

- [ ] Options page configured with production API URL
- [ ] Device login flow tested (`Connect SafeSpend` -> approve -> scan works)
- [ ] Installed extension verifies scan on known domains
- [ ] Package generated: `./scripts/package-extension.ps1`
- [ ] Private beta upload completed

## Smoke Tests

- [ ] `POST /api/auth/device/start` works
- [ ] `POST /api/auth/device/poll` returns tokens after approval
- [ ] `POST /api/scan` works with auth token
- [ ] `GET /api/site/{domain}` returns latest scan
- [ ] `POST /api/site/{domain}/rescan` works
- [ ] `GET /api/sites` filters work
