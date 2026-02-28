const DEFAULT_API_BASE_URL = 'http://localhost:8000';
const DEFAULT_CACHE_TTL_HOURS = 24;
const CACHE_KEY = 'scan_cache';
const LATEST_RESULTS_KEY = 'latest_results';
const TAB_DOMAINS_KEY = 'tab_domains';
const CACHE_CLEANUP_KEY = 'last_cache_cleanup_at';

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

function storageRemove(area, keys) {
  return new Promise((resolve) => {
    chrome.storage[area].remove(keys, () => resolve());
  });
}

function normalizeDomain(domainOrUrl) {
  try {
    const url = new URL(domainOrUrl);
    return url.hostname.replace(/^www\./, '').toLowerCase();
  } catch (_error) {
    return String(domainOrUrl || '').replace(/^www\./, '').toLowerCase();
  }
}

function randomInstallHash() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeNumber(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return parsed;
}

function buildRequestHeaders(apiToken) {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (apiToken) {
    headers['X-API-Token'] = apiToken;
  }

  return headers;
}

async function ensureInstallHash() {
  const data = await storageGet('local', ['install_hash']);
  if (data.install_hash) {
    return data.install_hash;
  }

  const generated = randomInstallHash();
  await storageSet('local', { install_hash: generated });
  return generated;
}

async function getExtensionConfig() {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  const localData = await storageGet('local', ['api_token']);

  return {
    apiBaseUrl: syncData.api_base_url || DEFAULT_API_BASE_URL,
    apiToken: localData.api_token || '',
    cacheTtlHours: Math.max(1, safeNumber(syncData.cache_ttl_hours, DEFAULT_CACHE_TTL_HOURS))
  };
}

function badgeStyleForTrustLevel(trustLevel) {
  if (trustLevel === 'HIGH') {
    return { color: '#2E7D32', text: 'SAFE' };
  }
  if (trustLevel === 'MEDIUM') {
    return { color: '#F9A825', text: 'MED' };
  }
  return { color: '#C62828', text: 'RISK' };
}

async function clearBadge(tabId) {
  await chrome.action.setBadgeText({ tabId, text: '' });
}

async function setBadge(tabId, result) {
  const style = badgeStyleForTrustLevel(result?.trust_level || 'LOW');
  await chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
  await chrome.action.setBadgeText({ tabId, text: String(result?.risk_score ?? style.text) });
}

async function getCache() {
  const data = await storageGet('local', [CACHE_KEY]);
  return data[CACHE_KEY] || {};
}

async function setCache(cache) {
  await storageSet('local', { [CACHE_KEY]: cache });
}

async function getLatestResults() {
  const data = await storageGet('local', [LATEST_RESULTS_KEY]);
  return data[LATEST_RESULTS_KEY] || {};
}

async function setLatestResults(latestResults) {
  await storageSet('local', { [LATEST_RESULTS_KEY]: latestResults });
}

async function getTabDomains() {
  const data = await storageGet('local', [TAB_DOMAINS_KEY]);
  return data[TAB_DOMAINS_KEY] || {};
}

async function setTabDomains(tabDomains) {
  await storageSet('local', { [TAB_DOMAINS_KEY]: tabDomains });
}

function addCacheMetadata(result, fromCache, staleCache = false) {
  return {
    ...result,
    from_cache: fromCache,
    stale_cache: staleCache
  };
}

async function cleanupExpiredCache(force = false) {
  const now = Date.now();
  const meta = await storageGet('local', [CACHE_CLEANUP_KEY]);
  const lastCleanup = safeNumber(meta[CACHE_CLEANUP_KEY], 0);

  // Run cleanup at most once every 6 hours unless forced.
  if (!force && now - lastCleanup < 6 * 60 * 60 * 1000) {
    return;
  }

  const { cacheTtlHours } = await getExtensionConfig();
  const ttlMs = cacheTtlHours * 60 * 60 * 1000;
  const maxAgeMs = ttlMs * 2;
  const cache = await getCache();
  const cleaned = {};

  for (const [domain, entry] of Object.entries(cache)) {
    if (!entry?.timestamp) continue;
    if (now - entry.timestamp <= maxAgeMs) {
      cleaned[domain] = entry;
    }
  }

  await storageSet('local', {
    [CACHE_CLEANUP_KEY]: now,
    [CACHE_KEY]: cleaned
  });
}

async function postSeenTelemetry(domain, installHash, config) {
  try {
    await fetch(`${config.apiBaseUrl}/api/telemetry/seen`, {
      method: 'POST',
      headers: buildRequestHeaders(config.apiToken),
      body: JSON.stringify({
        domain,
        user_install_hash: installHash
      })
    });
  } catch (_error) {
    // Telemetry is best-effort and should never block UX.
  }
}

async function requestScan(domain, signals, installHash, config) {
  const extensionVersion = chrome.runtime.getManifest().version;

  const response = await fetch(`${config.apiBaseUrl}/api/scan`, {
    method: 'POST',
    headers: buildRequestHeaders(config.apiToken),
    body: JSON.stringify({
      domain,
      extracted_signals: signals,
      extension_version: extensionVersion,
      user_install_hash: installHash,
      triggered_by: 'USER_VISIT'
    })
  });

  if (!response.ok) {
    throw new Error(`Scan API failed: ${response.status}`);
  }

  return await response.json();
}

function shouldUseCacheEntry(cachedEntry, htmlHash, ttlMs, now) {
  if (!cachedEntry?.timestamp || !cachedEntry?.result) {
    return false;
  }

  if (now - cachedEntry.timestamp >= ttlMs) {
    return false;
  }

  // If both hashes are present and changed, force a fresh scan.
  if (cachedEntry.html_hash && htmlHash && cachedEntry.html_hash !== htmlHash) {
    return false;
  }

  return true;
}

async function resolveScanForDomain(tabId, domain, signals) {
  const now = Date.now();
  const config = await getExtensionConfig();
  const ttlMs = config.cacheTtlHours * 60 * 60 * 1000;
  const htmlHash = signals?.html_hash || null;
  const cache = await getCache();
  const cachedEntry = cache[domain];

  if (shouldUseCacheEntry(cachedEntry, htmlHash, ttlMs, now)) {
    const cachedResult = addCacheMetadata(cachedEntry.result, true, false);
    await setBadge(tabId, cachedResult);
    return cachedResult;
  }

  const installHash = await ensureInstallHash();
  await postSeenTelemetry(domain, installHash, config);

  try {
    const freshResult = addCacheMetadata(await requestScan(domain, signals, installHash, config), false, false);

    cache[domain] = {
      timestamp: now,
      html_hash: htmlHash,
      result: freshResult
    };
    await setCache(cache);
    await setBadge(tabId, freshResult);
    return freshResult;
  } catch (error) {
    if (cachedEntry?.result) {
      const staleResult = addCacheMetadata(cachedEntry.result, true, true);
      await setBadge(tabId, staleResult);
      return staleResult;
    }
    throw error;
  }
}

async function clearTabState(tabId) {
  const tabDomains = await getTabDomains();
  delete tabDomains[String(tabId)];
  await setTabDomains(tabDomains);

  await clearBadge(tabId);
}

chrome.runtime.onInstalled.addListener(async () => {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  const localData = await storageGet('local', ['api_token']);

  const nextDefaults = {};
  if (!syncData.api_base_url) {
    nextDefaults.api_base_url = DEFAULT_API_BASE_URL;
  }
  if (!syncData.cache_ttl_hours) {
    nextDefaults.cache_ttl_hours = DEFAULT_CACHE_TTL_HOURS;
  }

  if (Object.keys(nextDefaults).length) {
    await storageSet('sync', nextDefaults);
  }

  if (typeof localData.api_token !== 'string') {
    await storageSet('local', { api_token: '' });
  }

  await ensureInstallHash();
  await cleanupExpiredCache(true);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearTabState(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'PAGE_SIGNALS') {
    (async () => {
      try {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ ok: false, error: 'Missing tab id.' });
          return;
        }

        const domain = normalizeDomain(message.payload.domain || sender.tab?.url || '');
        if (!domain) {
          sendResponse({ ok: false, error: 'Could not resolve domain.' });
          return;
        }

        const tabDomains = await getTabDomains();
        tabDomains[String(tabId)] = domain;
        await setTabDomains(tabDomains);

        const scanResult = await resolveScanForDomain(tabId, domain, message.payload.signals || {});

        const latestResults = await getLatestResults();
        latestResults[domain] = {
          scanned_at: Date.now(),
          result: scanResult
        };
        await setLatestResults(latestResults);

        await cleanupExpiredCache();

        sendResponse({ ok: true, domain, result: scanResult });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Scan failed.' });
      }
    })();

    return true;
  }

  if (message?.type === 'NOT_ECOMMERCE') {
    (async () => {
      const tabId = sender.tab?.id;
      if (typeof tabId === 'number') {
        await clearTabState(tabId);
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === 'GET_RESULT_FOR_ACTIVE_TAB') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ ok: false, error: 'No active tab.' });
          return;
        }

        const tabDomains = await getTabDomains();
        const domain = tabDomains[String(tabId)] || normalizeDomain(tab?.url || '');
        if (!domain) {
          sendResponse({ ok: false, error: 'No domain found for tab.' });
          return;
        }

        const latestResults = await getLatestResults();
        const cached = latestResults[domain];
        if (cached?.result) {
          sendResponse({ ok: true, domain, result: cached.result });
          return;
        }

        const cache = await getCache();
        const cacheEntry = cache[domain];
        if (cacheEntry?.result) {
          sendResponse({ ok: true, domain, result: addCacheMetadata(cacheEntry.result, true, false) });
          return;
        }

        sendResponse({ ok: false, error: 'No scan result found yet for this tab.' });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Unable to load tab result.' });
      }
    })();

    return true;
  }

  if (message?.type === 'GET_EXTENSION_CONFIG') {
    (async () => {
      const config = await getExtensionConfig();
      const local = await storageGet('local', ['install_hash']);
      sendResponse({
        ok: true,
        config,
        install_hash: local.install_hash || null
      });
    })();
    return true;
  }

  if (message?.type === 'CLEAR_EXTENSION_CACHE') {
    (async () => {
      await storageRemove('local', [CACHE_KEY, LATEST_RESULTS_KEY]);
      sendResponse({ ok: true });
    })();
    return true;
  }

  return false;
});
