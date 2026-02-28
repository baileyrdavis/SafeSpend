# SafeSpend Extension

Manifest V3 Chrome extension for in-browser e-commerce risk checks.

## Files

- `content.js`: page signal extraction (cart, checkout, policy/contact hints, hash)
- `background.js`: auth flow, caching, API requests, badge updates
- `popup.*`: consumer score view and account connect action
- `options.*`: backend URL, account connection, cache controls

## Local Load

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked from this `extension/` directory
4. Open extension settings and set API URL if needed
5. Click `Connect SafeSpend` once to authorize this browser profile

## Security Notes

- Extension stores only:
  - install hash
  - short-lived access/refresh tokens
  - summary scan cache
- Full check breakdown is fetched on-demand and not persisted in local cache
- Non-localhost HTTP URLs are blocked in settings; use HTTPS for production
- Extension pages enforce `script-src 'self'` via manifest CSP
