# API Reference (MVP)

Base path: `/api`

## Health

### `GET /health`
Returns service status.

## Extension Auth (Device Flow)

### `POST /auth/device/start`
Starts extension login flow.

Request:

```json
{
  "install_hash": "f60be8c0...",
  "extension_version": "0.1.0"
}
```

Response:

```json
{
  "device_code": "opaque-device-code",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://api.example.com/auth/device/verify",
  "verification_uri_complete": "https://api.example.com/auth/device/verify?user_code=ABCD-EFGH",
  "expires_in": 900,
  "interval": 5
}
```

### `POST /auth/device/poll`
Polls for device approval and exchanges for token pair.

Request:

```json
{
  "device_code": "opaque-device-code",
  "install_hash": "f60be8c0..."
}
```

Pending response: `428` with `error=authorization_pending`.
Approved response: returns access + refresh tokens.

### `POST /auth/token/refresh`
Rotates refresh token and returns a fresh access token pair.

### `GET /auth/session`
Checks if current Bearer token is valid.

### `POST /auth/logout`
Revokes active token family for the current install.

## Scanning

### `POST /scan`

Request:

```json
{
  "domain": "example.com",
  "extracted_signals": {},
  "extension_version": "0.1.0",
  "user_install_hash": "abc123",
  "triggered_by": "USER_VISIT",
  "include_checks": false,
  "include_evidence": false
}
```

Response includes:

- `domain`
- `risk_score`
- `trust_level`
- `top_reasons`
- `score_confidence`
- `last_scanned_at`
- `from_cache`
- `disclaimer`
- `checks` (empty by default unless `include_checks=true`)

## Index + Lookup

### `GET /site/{domain}`
Returns indexed site detail and latest scan check breakdown.

### `POST /site/{domain}/rescan`
Forces an indexed domain re-scan.

### `GET /sites`
Query params:

- `limit` (default 50, max 200)
- `trust_level` (`LOW` | `MEDIUM` | `HIGH`)
- `min_risk_score` (0-100)
- `q` (domain contains)

### `POST /telemetry/seen`
Records seen domain + install hash.
When 3 unique install hashes are seen, domain is promoted to indexed `Site`.

## Authentication

Protected endpoints require one of:

1. `Authorization: Bearer <access_token>` from device flow
2. `X-API-Token: <static_token>` (optional fallback for admin/internal tools)

`/health` and device auth start/poll/refresh are publicly callable by design.
