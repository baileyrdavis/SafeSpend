# SafeSpend

SafeSpend is a deterministic browser-based e-commerce risk detection system focused on explainable scoring and low-cost operations.

## What Is Included

- Django + DRF backend API
- PostgreSQL data model (scan history + evidence + indexed sites)
- Deterministic modular risk engine (10 checks)
- Country-aware framework (AU / US / UK)
- Chrome Extension (Manifest V3)
- Docker + Docker Compose local stack
- Railway deployment config (`backend/railway.toml`)
- CI, security, CodeQL, and Dependabot GitHub setup

## Core Backend Features

- Settings split by environment (`config.settings.dev/prod/test`)
- Models: `Site`, `Scan`, `CheckResult`, `EvidenceSnapshot`, `SeenSite`
- Auth models: `DeviceAuthSession`, `ApiAccessToken`, `ApiRefreshToken`
- Session-backed device verification flow for extension login
- Opaque hashed token auth with refresh rotation and revocation
- Risk score clamped to 0-100 with evidence-backed explanations
- Neutral terminology + disclaimer in scan responses
- `SeenSite` promotion logic (3 unique installs => index + scan)
- Re-scan triggers: 7-day staleness or hash-change
- Scoped API throttling for scan/auth/lookup endpoints

## API Endpoints

- `GET /api/health`
- `POST /api/auth/device/start`
- `POST /api/auth/device/poll`
- `POST /api/auth/token/refresh`
- `GET /api/auth/session`
- `POST /api/auth/logout`
- `POST /api/scan`
- `GET /api/site/{domain}`
- `POST /api/site/{domain}/rescan`
- `GET /api/sites`
- `POST /api/telemetry/seen`

Full examples: [docs/API.md](docs/API.md)

## Extension Features

- Detects likely e-commerce pages (cart/checkout/schema/content signals)
- Extracts lightweight signals and homepage HTML hash
- One-click guided account connection (`Connect SafeSpend`)
- Stores only short-lived auth tokens + summary cache
- Fetches detailed check breakdown on demand
- 24h configurable cache with hash-aware invalidation
- Badge color + score display

## Local Development

```bash
docker compose up --build
```

Local URLs:

- Backend: `http://localhost:8000`
- Postgres: `localhost:5432`

## Testing

See [docs/TESTING.md](docs/TESTING.md)

Quick commands:

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.test python manage.py check && DJANGO_SETTINGS_MODULE=config.settings.test python manage.py test
```

## Deployment (Supabase + Railway + R2)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

Quick summary:

1. Provision Supabase Postgres and copy `DATABASE_URL`.
2. Deploy `backend/` to Railway with Docker.
3. Configure backend env vars (`API_REQUIRE_AUTH`, CORS, secure flags).
4. Set Cloudflare R2 vars if enabling object storage expansion.
5. Update extension API URL and connect via device auth flow.

Release checklist: [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)
GitHub setup: [docs/GITHUB_SETUP.md](docs/GITHUB_SETUP.md)

## Safety Notice

Risk scores are informational only and must not be treated as definitive fraud labels.
