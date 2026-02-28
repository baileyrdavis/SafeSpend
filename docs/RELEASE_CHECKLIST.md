# Release Checklist

## Backend

- [ ] `DEBUG=False`
- [ ] `DJANGO_SETTINGS_MODULE=config.settings.prod`
- [ ] Strong `DJANGO_SECRET_KEY`
- [ ] `ALLOWED_HOSTS` includes production hosts only
- [ ] `CORS_ALLOW_ALL_ORIGINS=False`
- [ ] `CORS_ALLOWED_ORIGINS` locked to portal + extension origin
- [ ] `CSRF_TRUSTED_ORIGINS` configured
- [ ] `DATABASE_URL` points to Neon
- [ ] Optional `API_AUTH_TOKEN` configured and distributed to portal/extension
- [ ] `GET /api/health` verified in production

## Risk Engine Operations

- [ ] Recheck cron configured: `python manage.py recheck_sites --days 7 --limit 500`
- [ ] Logs monitored for WHOIS/DNS/network failure spikes

## Portal

- [ ] `VITE_API_BASE_URL` points to production backend
- [ ] `VITE_API_TOKEN` set if backend token enabled
- [ ] Portal build passes: `npm run build`

## Extension

- [ ] Options page configured with production API URL/token
- [ ] Installed extension verifies scan on known domains
- [ ] Package generated: `./scripts/package-extension.ps1`
- [ ] Private beta upload completed

## Smoke Tests

- [ ] `POST /api/scan` works with production domain
- [ ] `GET /api/site/{domain}` returns latest scan
- [ ] `POST /api/site/{domain}/rescan` works
- [ ] `GET /api/sites` filters work
