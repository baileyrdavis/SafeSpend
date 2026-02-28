# Testing Guide

## 1) Prerequisites

- Docker Desktop running
- Chrome/Chromium for extension tests

## 2) Local End-to-End (Docker)

From repository root:

```bash
docker compose up --build
```

Services:

- Backend API: `http://localhost:8000`
- Portal: `http://localhost:5173`
- Postgres: `localhost:5432`

Health check:

```bash
curl http://localhost:8000/api/health
```

## 3) Create Admin User (for auth flow test)

```bash
docker compose exec backend python manage.py createsuperuser
```

## 4) Backend Test Suite

From `backend/`:

```bash
DJANGO_SETTINGS_MODULE=config.settings.test python manage.py check
DJANGO_SETTINGS_MODULE=config.settings.test python manage.py test
```

## 5) Portal Build Verification

From `portal/`:

```bash
npm install
npm run build
```

## 6) Extension Test Flow

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Load unpacked extension from `extension/`
4. Open extension settings:
   - API Base URL: `http://localhost:8000`
5. Visit an e-commerce site
6. Open popup and click `Connect SafeSpend`
7. Complete sign-in in opened tab (`/auth/device/verify`)
8. Return to popup and verify:
   - risk score appears
   - trust level color appears
   - top reasons list appears
   - detailed breakdown loads on demand

## 7) API Manual Checks

### Start device auth

```bash
curl -X POST http://localhost:8000/api/auth/device/start \
  -H "Content-Type: application/json" \
  -d '{"install_hash":"install-hash-for-manual-test"}'
```

### Trigger scan (authenticated)

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access-token>" \
  -d '{
    "domain": "example.com",
    "extension_version": "manual-test",
    "triggered_by": "MANUAL_LOOKUP",
    "include_checks": false,
    "extracted_signals": {"is_ecommerce": true}
  }'
```

### Lookup indexed site

```bash
curl http://localhost:8000/api/site/example.com \
  -H "Authorization: Bearer <access-token>"
```

### Seen telemetry

```bash
curl -X POST http://localhost:8000/api/telemetry/seen \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access-token>" \
  -d '{"domain":"example.com","user_install_hash":"install-a"}'
```
