const DEFAULT_API_BASE_URL = 'http://localhost:8000';
const DEFAULT_CACHE_TTL_HOURS = 24;

function byId(id) {
  return document.getElementById(id);
}

function storageGet(area, keys) {
  return new Promise((resolve) => {
    chrome.storage[area].get(keys, (result) => resolve(result));
  });
}

function storageSet(area, values) {
  return new Promise((resolve) => {
    chrome.storage[area].set(values, () => resolve());
  });
}

function setStatus(message, type = 'success') {
  const status = byId('status');
  status.className = `status ${type}`;
  status.textContent = message;
}

async function loadSettings() {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  const localData = await storageGet('local', ['install_hash', 'api_token']);

  byId('apiBaseUrl').value = syncData.api_base_url || DEFAULT_API_BASE_URL;
  byId('apiToken').value = localData.api_token || '';
  byId('cacheTtlHours').value = String(syncData.cache_ttl_hours || DEFAULT_CACHE_TTL_HOURS);
  byId('installHash').textContent = localData.install_hash || 'Not initialized yet.';
}

async function saveSettings() {
  const apiBaseUrl = byId('apiBaseUrl').value.trim().replace(/\/$/, '');
  const apiToken = byId('apiToken').value.trim();
  const cacheTtlHoursRaw = Number(byId('cacheTtlHours').value);
  const cacheTtlHours = Math.max(1, Math.min(72, Number.isFinite(cacheTtlHoursRaw) ? cacheTtlHoursRaw : DEFAULT_CACHE_TTL_HOURS));

  if (!apiBaseUrl) {
    setStatus('API base URL is required.', 'error');
    return;
  }

  const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(apiBaseUrl);
  const isHttps = apiBaseUrl.startsWith('https://');
  if (!isHttps && !isLocalhost) {
    setStatus('Use HTTPS for non-localhost API URLs.', 'error');
    return;
  }

  await storageSet('sync', {
    api_base_url: apiBaseUrl,
    cache_ttl_hours: cacheTtlHours
  });
  await storageSet('local', { api_token: apiToken });

  setStatus('Settings saved.');
}

async function testConnection() {
  const apiBaseUrl = byId('apiBaseUrl').value.trim().replace(/\/$/, '');
  const apiToken = byId('apiToken').value.trim();

  if (!apiBaseUrl) {
    setStatus('Enter API base URL before testing.', 'error');
    return;
  }

  const headers = {};
  if (apiToken) {
    headers['X-API-Token'] = apiToken;
  }

  try {
    const response = await fetch(`${apiBaseUrl}/api/health`, { headers });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    setStatus('Connection OK.');
  } catch (error) {
    setStatus(`Connection failed: ${error.message || 'unknown error'}`, 'error');
  }
}

async function clearCache() {
  await chrome.runtime.sendMessage({ type: 'CLEAR_EXTENSION_CACHE' });
  setStatus('Cached scan results cleared.');
}

byId('saveBtn').addEventListener('click', saveSettings);
byId('testBtn').addEventListener('click', testConnection);
byId('clearCacheBtn').addEventListener('click', clearCache);

loadSettings();
