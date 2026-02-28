# SafeSpend Extension

Manifest V3 Chrome extension for in-browser e-commerce risk checks.

## Files

- `content.js`: page signal extraction (cart, checkout, policy/contact hints, hash)
- `background.js`: auth flow, caching, API requests, badge updates
- `popup.*`: consumer score view and account connect action
- `options.*`: account connection, cache controls, advanced backend override
- `runtime_config.js`: publish-time backend URL config

## Local Load

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked from this `extension/` directory
4. Set `API_BASE_URL` in `runtime_config.js` before packaging/publishing
5. Click `Connect SafeSpend` once to authorize this browser profile

## Security Notes

- Extension stores only:
  - install hash
  - short-lived access/refresh tokens
  - summary scan cache
- Full check breakdown is fetched on-demand and not persisted in local cache
- Backend URL is auto-configured from `runtime_config.js`; end users do not need to set it
- Non-localhost HTTP URLs are blocked in advanced override; use HTTPS for production
- Extension pages enforce `script-src 'self'` via manifest CSP
