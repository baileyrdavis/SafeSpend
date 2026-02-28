export function createApiClient(apiBaseUrl, apiToken) {
  const activeBaseUrl = String(apiBaseUrl || '').replace(/\/$/, '');

  function buildHeaders(extraHeaders = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...extraHeaders
    };

    if ((apiToken || '').trim()) {
      headers['X-API-Token'] = apiToken.trim();
    }

    return headers;
  }

  async function fetchJson(path, options = {}) {
    const response = await fetch(`${activeBaseUrl}${path}`, {
      ...options,
      headers: buildHeaders(options.headers || {})
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }

    if (!response.ok) {
      const message = payload?.detail || payload?.error || `Request failed (${response.status})`;
      throw new Error(message);
    }

    return payload;
  }

  return {
    fetchJson,
    activeBaseUrl
  };
}