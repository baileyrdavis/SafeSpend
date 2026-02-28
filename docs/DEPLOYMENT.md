# Deployment Guide (Neon + Railway + Cloudflare R2)

## Deployment Architecture

- Backend: Railway (Docker deploy from `backend/`)
- Database: Neon PostgreSQL (`DATABASE_URL`)
- Object Storage: Cloudflare R2 (optional for current MVP, ready for expansion)
- Extension: private Chrome extension package from `extension/`

## 1) Neon Setup

1. Create a Neon project and database.
2. Copy the connection string.
3. Ensure connection string includes SSL requirements expected by Neon.
4. Use this connection string as Railway `DATABASE_URL`.

## 2) Railway Backend Service

### Option A: Deploy from Git repo in Railway UI

1. Create a new Railway project.
2. Add a service from your repo.
3. Point service root to `backend/`.
4. Railway will use `backend/Dockerfile`.

### Option B: Railway CLI

1. `railway login`
2. `railway link`
3. `railway up`

`backend/railway.toml` is included with healthcheck and restart policy settings.

## 3) Required Railway Environment Variables

Set these in Railway service variables:

- `DJANGO_SECRET_KEY`
- `DJANGO_SETTINGS_MODULE=config.settings.prod`
- `DEBUG=False`
- `APP_VERSION=0.1.0`
- `ALLOWED_HOSTS=<your-railway-domain>,<your-custom-domain>`
- `DATABASE_URL=<your-neon-connection-string>`
- `CORS_ALLOW_ALL_ORIGINS=False`
- `CORS_ALLOWED_ORIGINS=http://localhost:5173,https://<your-portal-domain>,chrome-extension://<extension-id>`
- `CSRF_TRUSTED_ORIGINS=https://<your-backend-domain>,https://<your-portal-domain>`
- `API_AUTH_TOKEN=<optional-shared-token>`
- `LOG_LEVEL=INFO`

Generate a strong secret key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Recommended security envs:

- `SECURE_SSL_REDIRECT=True`
- `SECURE_HSTS_SECONDS=31536000`

## 4) Cloudflare R2 Setup (Optional for MVP)

Set in Railway backend service:

- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_BUCKET_NAME`
- `R2_ENDPOINT_URL=https://<account-id>.r2.cloudflarestorage.com`

Current MVP stores HTML hashes in Postgres; R2 settings are already wired for future snapshot/object storage needs.

## 5) Post-Deploy Validation

1. `GET /api/health` returns `status=ok`.
2. `POST /api/scan` succeeds for test domain.
3. Extension options updated with production API URL.
4. If token enabled, extension and portal token fields are set.

## 6) Portal Deployment Choices

- Keep portal local for internal admin use, OR
- Deploy `portal/` as a separate Railway/static service and set `VITE_API_BASE_URL` to backend URL.

If portal is public, protect backend with `API_AUTH_TOKEN` and restrict CORS.

## 7) Scheduled Rechecks (Recommended)

Run periodic command on Railway cron/job service:

```bash
python manage.py recheck_sites --days 7 --limit 500
```

Dry-run example:

```bash
python manage.py recheck_sites --dry-run
```

## 8) Extension Packaging for Beta

From repo root (PowerShell):

```powershell
./scripts/package-extension.ps1
```

This creates `ghost-store-guard-extension.zip` for private beta distribution.

## Platform References

- Railway config as code (`railway.toml`): https://docs.railway.com/reference/config-as-code
- Railway cron jobs: https://docs.railway.com/guides/cron-jobs
- Neon connection strings: https://neon.com/docs/connect/connection-uris
- Cloudflare R2 S3-compatible API: https://developers.cloudflare.com/r2/api/s3/api/
