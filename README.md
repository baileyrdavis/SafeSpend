# Ghost-Store Guard

Ghost-Store Guard is a deterministic browser-based fraud-risk detection system for e-commerce domains.

## What Is Included

- Django + DRF backend API
- PostgreSQL data model (scan history + evidence + indexed sites)
- Deterministic modular risk engine (10 checks)
- Country-aware framework (AU / US / UK)
- Chrome Extension (Manifest V3)
- Optional React portal for lookup/admin workflows
- Docker + Docker Compose local stack
- Railway deployment config (`backend/railway.toml`)
- CI workflow (`.github/workflows/ci.yml`)
- Security workflow (`.github/workflows/security.yml`)
- CodeQL workflow (`.github/workflows/codeql.yml`)
- Dependabot config (`.github/dependabot.yml`)

## Core Backend Features

- Django settings split by environment (`config.settings.dev/prod/test`)
- Models: `Site`, `Scan`, `CheckResult`, `EvidenceSnapshot`, `SeenSite`
- Risk score clamped to 0-100 with full evidence breakdown
- Neutral terminology and disclaimer in API responses
- `SeenSite` promotion logic (3 unique installs => index + scan)
- Re-scan triggers: 7-day staleness or hash-change
- Optional API token protection (`API_AUTH_TOKEN`)
- Scoped API throttling for `scan`, `telemetry`, `lookup`, and `rescan`
- Management command for scheduled rechecks: `recheck_sites`

## API Endpoints

- `GET /api/health`
- `POST /api/scan`
- `GET /api/site/{domain}`
- `POST /api/site/{domain}/rescan`
- `GET /api/sites`
- `POST /api/telemetry/seen`

See full API examples: [docs/API.md](docs/API.md)
Security notes: [docs/SECURITY_NOTES.md](docs/SECURITY_NOTES.md)

## Extension Features

- Detects likely e-commerce pages (cart/checkout/schema/content signals)
- Extracts lightweight signals and homepage HTML hash
- Calls backend scan API
- 24h configurable cache (hash-aware invalidation)
- Badge color + score display
- Popup with top reasons and full breakdown
- Options page for API URL, token, and cache controls

## Local Development

```bash
docker compose up --build
```

Local URLs:

- Backend: `http://localhost:8000`
- Portal: `http://localhost:5173`
- Postgres: `localhost:5432`

## Testing

See [docs/TESTING.md](docs/TESTING.md)

Quick commands:

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.test python manage.py check && DJANGO_SETTINGS_MODULE=config.settings.test python manage.py test
cd portal && npm install && npm run build
```

## Deployment (Neon + Railway + R2)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

Quick summary:

1. Provision Neon and copy connection string to `DATABASE_URL`.
2. Deploy `backend/` to Railway using Docker.
3. Configure backend env vars (`ALLOWED_HOSTS`, CORS, token, security flags).
4. Optionally set R2 env vars for storage expansion.
5. Update extension options with production API URL (and token if enabled).

Release checklist: [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)
GitHub setup: [docs/GITHUB_SETUP.md](docs/GITHUB_SETUP.md)

## Useful Scripts

- Extension package: `./scripts/package-extension.ps1`
- Full local test run (PowerShell): `./scripts/test-all.ps1`
- Make targets: `make test`, `make compose-up`

## Safety Notice

Risk scores are informational only and must not be treated as definitive fraud labels.
