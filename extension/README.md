# Ghost-Store Guard Extension

Manifest V3 Chrome extension for in-browser e-commerce risk scoring.

## Files

- `content.js`: page signal extraction (cart, checkout, policy/contact hints, hash)
- `background.js`: caching, API requests, badge updates, telemetry
- `popup.*`: score UI
- `options.*`: backend URL/token/cache configuration

## Local Load

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked from this `extension/` directory
4. Open extension settings to set backend URL/token

## Security Notes

- API token is stored in `chrome.storage.local` (not synced)
- Non-localhost HTTP URLs are blocked in settings; use HTTPS for production
- Extension pages enforce `script-src 'self'` via manifest CSP
