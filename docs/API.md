# API Reference (MVP)

Base path: `/api`

## GET `/health`
Returns service health status.
Response includes `status`, `timestamp`, and `version`.

## POST `/scan`
Request:

```json
{
  "domain": "example.com",
  "extracted_signals": {},
  "extension_version": "0.1.0",
  "user_install_hash": "abc123",
  "triggered_by": "USER_VISIT"
}
```

Response includes:

- `domain`
- `risk_score`
- `trust_level`
- `top_reasons`
- `checks`
- `score_confidence`
- `last_scanned_at`
- `from_cache`
- `disclaimer`

## GET `/site/{domain}`
Returns indexed site details and latest scan with full check breakdown.

## POST `/site/{domain}/rescan`
Triggers immediate re-scan of an indexed domain.

Request body (optional):

```json
{
  "extension_version": "portal-rescan",
  "extracted_signals": {}
}
```

## GET `/sites`
Query params:

- `limit` (default 50, max 200)
- `trust_level` (`LOW` | `MEDIUM` | `HIGH`)
- `min_risk_score` (0-100)
- `q` (domain contains)

## POST `/telemetry/seen`
Request:

```json
{
  "domain": "example.com",
  "user_install_hash": "client-install-id"
}
```

When 3 unique install hashes are observed for a domain, it is promoted to indexed `Site`.

## Authentication

If `API_AUTH_TOKEN` is configured, include either:

- `X-API-Token: <token>`
- `Authorization: Bearer <token>`

`/health` remains publicly accessible.
