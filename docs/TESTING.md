# Testing Guide

## 1) Local Environment Prerequisites

- Docker Desktop running
- Python 3.12+ (if running backend outside Docker)
- Node 20+ (if running portal outside Docker)
- Chrome/Chromium (for extension testing)

## 2) Fast End-to-End Test via Docker

From repository root:

```bash
docker compose up --build
```

Expected services:

- Backend API: `http://localhost:8000`
- Portal: `http://localhost:5173`
- Postgres: `localhost:5432`

Quick health check:

```bash
curl http://localhost:8000/api/health
```

You should get `{"status":"ok", ...}`.

## 3) Backend Test Suite

From `backend/`:

```bash
DJANGO_SETTINGS_MODULE=config.settings.test python manage.py check
DJANGO_SETTINGS_MODULE=config.settings.test python manage.py test
```

## 4) Portal Build Verification

From `portal/`:

```bash
npm install
npm run build
```

## 5) Extension Test Flow

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Load unpacked extension from `extension/`
4. Open extension settings and set:
   - API Base URL: `http://localhost:8000`
   - API Token: blank unless configured on backend
5. Visit an e-commerce site.
6. Open popup and verify:
   - risk score visible
   - trust level color
   - top reasons + detailed checks

## 6) API Manual Checks

### Trigger scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "extension_version": "manual-test",
    "triggered_by": "MANUAL_LOOKUP",
    "extracted_signals": {"is_ecommerce": true}
  }'
```

### Lookup indexed site

```bash
curl http://localhost:8000/api/site/example.com
```

### Force indexed rescan

```bash
curl -X POST http://localhost:8000/api/site/example.com/rescan \
  -H "Content-Type: application/json" \
  -d '{"extension_version": "manual-rescan"}'
```

### Seen telemetry

```bash
curl -X POST http://localhost:8000/api/telemetry/seen \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "user_install_hash": "install-a"}'
```

## 7) Token-Protected Mode Test

If `API_AUTH_TOKEN` is set in backend env, all non-health endpoints require:

- `X-API-Token: <token>` header

Example:

```bash
curl http://localhost:8000/api/sites -H "X-API-Token: your-token"
```
