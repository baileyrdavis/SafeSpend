# Deployment Guide (Supabase + Railway + Cloudflare R2)

## Deployment Architecture

- Backend: Railway (Docker deploy from `backend/`)
- Database: Supabase PostgreSQL (`DATABASE_URL`)
- Object Storage: Cloudflare R2 (optional for MVP, ready for expansion)
- Extension: packaged from `extension/` and privately distributed

## 1) Supabase Setup

1. Create a Supabase project.
2. Open project settings and copy the Postgres connection URI.
3. Use connection pooling URI if your traffic model benefits from pooling.
4. Set this URI as Railway `DATABASE_URL`.

## 2) Railway Backend Service

### Option A: Railway UI

1. Create Railway project.
2. Add service from your GitHub repo.
3. Set service root to `backend/`.
4. Railway builds using `backend/Dockerfile`.

### Option B: Railway CLI

1. `railway login`
2. `railway link`
3. `railway up`

`backend/railway.toml` is included with healthcheck/restart settings.

## 3) Required Railway Environment Variables

- `DJANGO_SECRET_KEY`
- `DJANGO_SETTINGS_MODULE=config.settings.prod`
- `DEBUG=False`
- `APP_VERSION=0.1.0`
- `ALLOWED_HOSTS=<railway-domain>,<custom-domain>`
- `DATABASE_URL=<supabase-connection-string>`
- `CORS_ALLOW_ALL_ORIGINS=False`
- `CORS_ALLOWED_ORIGINS=chrome-extension://<extension-id>`
- `CSRF_TRUSTED_ORIGINS=https://<backend-domain>`
- `API_REQUIRE_AUTH=True`
- `API_AUTH_TOKEN=` (optional static fallback)
- `DEVICE_AUTH_EXPIRES_SECONDS=900`
- `DEVICE_AUTH_INTERVAL_SECONDS=5`
- `API_ACCESS_TOKEN_EXPIRES_SECONDS=900`
- `API_REFRESH_TOKEN_EXPIRES_SECONDS=2592000`
- `LOG_LEVEL=INFO`
- `SECURE_SSL_REDIRECT=True`
- `SECURE_HSTS_SECONDS=31536000`

Generate Django secret:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## 4) Create Admin User

Required for first-time extension sign-in approvals.

```bash
python manage.py createsuperuser
```

Users approve extension sessions at `/auth/device/verify`.

## 5) Cloudflare R2 Setup (Optional for MVP)

Set Railway env vars:

- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_BUCKET_NAME`
- `R2_ENDPOINT_URL=https://<account-id>.r2.cloudflarestorage.com`

MVP currently stores HTML hash evidence in Postgres; R2 is pre-wired for future object snapshots.

## 6) Post-Deploy Validation

1. `GET /api/health` returns `status=ok`.
2. Extension settings API URL points to production backend.
3. Extension `Connect SafeSpend` opens `/auth/device/verify`.
4. Approved extension can scan and show score/reasons.

## 7) Scheduled Rechecks

Use Railway cron/job service:

```bash
python manage.py recheck_sites --days 7 --limit 500
```

Dry run:

```bash
python manage.py recheck_sites --dry-run
```

## 8) Extension Package for Beta

From repo root (PowerShell):

```powershell
./scripts/package-extension.ps1
```

Creates `safespend-extension.zip`.

## Platform References

- Railway config as code: https://docs.railway.com/reference/config-as-code
- Railway cron jobs: https://docs.railway.com/guides/cron-jobs
- Supabase DB connection strings: https://supabase.com/docs/guides/database/connecting-to-postgres
- Cloudflare R2 S3 API: https://developers.cloudflare.com/r2/api/s3/api/
