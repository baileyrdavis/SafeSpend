const DEFAULT_API_BASE_URL = 'http://localhost:8000';
const DEFAULT_CACHE_TTL_HOURS = 24;

const STORAGE_KEYS = {
  CACHE: 'scan_cache',
  TAB_DOMAINS: 'tab_domains',
  INSTALL_HASH: 'install_hash',
  CACHE_CLEANUP_AT: 'last_cache_cleanup_at',
  AUTH_STATE: 'auth_state',
  DEVICE_AUTH: 'device_auth_session'
};

const CLOCK_SKEW_MS = 45 * 1000;
const CACHE_CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;

let authPollTimer = null;

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
  return Array.from(bytes).map((value) => value.toString(16).padStart(2, '0')).join('');
}

function safeNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function createAuthRequiredError() {
  const error = new Error('Sign in is required before scanning.');
  error.code = 'auth_required';
  return error;
}

function buildHeaders(accessToken = '', includeJson = true) {
  const headers = {};
  if (includeJson) {
    headers['Content-Type'] = 'application/json';
  }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  return headers;
}

function isFreshTimestamp(timestampMs) {
  return safeNumber(timestampMs, 0) - Date.now() > CLOCK_SKEW_MS;
}

function trustBadgeStyle(trustLevel) {
  if (trustLevel === 'HIGH') {
    return { color: '#2E7D32', text: 'SAFE' };
  }
  if (trustLevel === 'MEDIUM') {
    return { color: '#F9A825', text: 'MED' };
  }
  return { color: '#C62828', text: 'RISK' };
}

function sanitizeReason(value) {
  return {
    check_name: String(value?.check_name || 'Unknown check'),
    risk_points: safeNumber(value?.risk_points, 0),
    severity: String(value?.severity || 'INFO'),
    explanation: String(value?.explanation || 'No explanation available.')
  };
}

function sanitizeSummaryResult(payload) {
  return {
    risk_score: safeNumber(payload?.risk_score, 0),
    trust_level: String(payload?.trust_level || 'MEDIUM'),
    score_confidence: safeNumber(payload?.score_confidence, 0),
    last_scanned_at: payload?.last_scanned_at || null,
    disclaimer: payload?.disclaimer || 'Risk score is informational only.',
    top_reasons: Array.isArray(payload?.top_reasons) ? payload.top_reasons.slice(0, 3).map(sanitizeReason) : []
  };
}

function withResultMetadata(result, fromCache, staleCache = false) {
  return {
    ...result,
    from_cache: fromCache,
    stale_cache: staleCache
  };
}

async function getExtensionConfig() {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  return {
    apiBaseUrl: (syncData.api_base_url || DEFAULT_API_BASE_URL).replace(/\/$/, ''),
    cacheTtlHours: Math.max(1, safeNumber(syncData.cache_ttl_hours, DEFAULT_CACHE_TTL_HOURS))
  };
}

async function ensureInstallHash() {
  const localData = await storageGet('local', [STORAGE_KEYS.INSTALL_HASH]);
  if (localData[STORAGE_KEYS.INSTALL_HASH]) {
    return localData[STORAGE_KEYS.INSTALL_HASH];
  }

  const generated = randomInstallHash();
  await storageSet('local', { [STORAGE_KEYS.INSTALL_HASH]: generated });
  return generated;
}

async function getCache() {
  const localData = await storageGet('local', [STORAGE_KEYS.CACHE]);
  return localData[STORAGE_KEYS.CACHE] || {};
}

async function setCache(cacheValue) {
  await storageSet('local', { [STORAGE_KEYS.CACHE]: cacheValue });
}

async function getTabDomains() {
  const localData = await storageGet('local', [STORAGE_KEYS.TAB_DOMAINS]);
  return localData[STORAGE_KEYS.TAB_DOMAINS] || {};
}

async function setTabDomains(tabDomains) {
  await storageSet('local', { [STORAGE_KEYS.TAB_DOMAINS]: tabDomains });
}

async function getAuthState() {
  const localData = await storageGet('local', [STORAGE_KEYS.AUTH_STATE]);
  return localData[STORAGE_KEYS.AUTH_STATE] || {};
}

async function setAuthState(nextState) {
  await storageSet('local', { [STORAGE_KEYS.AUTH_STATE]: nextState });
}

async function clearAuthState() {
  await storageRemove('local', [STORAGE_KEYS.AUTH_STATE]);
}

async function getDeviceAuthSession() {
  const localData = await storageGet('local', [STORAGE_KEYS.DEVICE_AUTH]);
  return localData[STORAGE_KEYS.DEVICE_AUTH] || null;
}

async function setDeviceAuthSession(session) {
  await storageSet('local', { [STORAGE_KEYS.DEVICE_AUTH]: session });
}

async function clearDeviceAuthSession() {
  await storageRemove('local', [STORAGE_KEYS.DEVICE_AUTH]);
}

async function cleanupExpiredCache(force = false) {
  const now = Date.now();
  const localData = await storageGet('local', [STORAGE_KEYS.CACHE_CLEANUP_AT]);
  const lastCleanupAt = safeNumber(localData[STORAGE_KEYS.CACHE_CLEANUP_AT], 0);

  if (!force && now - lastCleanupAt < CACHE_CLEANUP_INTERVAL_MS) {
    return;
  }

  const { cacheTtlHours } = await getExtensionConfig();
  const ttlMs = cacheTtlHours * 60 * 60 * 1000;
  const maxAgeMs = ttlMs * 2;
  const existingCache = await getCache();
  const cleanedCache = {};

  for (const [domain, entry] of Object.entries(existingCache)) {
    if (!entry?.timestamp || !entry?.summary) continue;
    if (now - entry.timestamp <= maxAgeMs) {
      cleanedCache[domain] = entry;
    }
  }

  await storageSet('local', {
    [STORAGE_KEYS.CACHE_CLEANUP_AT]: now,
    [STORAGE_KEYS.CACHE]: cleanedCache
  });
}

async function setBadge(tabId, result) {
  const style = trustBadgeStyle(result?.trust_level || 'LOW');
  await chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
  await chrome.action.setBadgeText({ tabId, text: String(result?.risk_score ?? style.text) });
}

async function clearBadge(tabId) {
  await chrome.action.setBadgeText({ tabId, text: '' });
}

async function clearTabState(tabId) {
  const tabDomains = await getTabDomains();
  delete tabDomains[String(tabId)];
  await setTabDomains(tabDomains);
  await clearBadge(tabId);
}

async function triggerActiveTabExtraction() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== 'number') {
      return;
    }
    await chrome.tabs.sendMessage(tab.id, { type: 'RUN_EXTRACTION' });
  } catch (_error) {
    // Best-effort refresh. Some tabs may not host content script.
  }
}

function authStatePayload(authState, deviceSession) {
  const now = Date.now();
  const authenticated = Boolean(authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms));
  const refreshAvailable = Boolean(authState?.refresh_token && safeNumber(authState.refresh_expires_at_ms, 0) > now);
  const sessionPending = Boolean(deviceSession && deviceSession.status === 'pending' && deviceSession.expires_at_ms > now);

  return {
    authenticated,
    refresh_available: refreshAvailable,
    in_progress: sessionPending,
    user_code: sessionPending ? deviceSession.user_code : null,
    verification_url: sessionPending ? deviceSession.verification_uri_complete : null,
    auth_error: deviceSession?.status === 'failed' ? deviceSession.error || 'Authorization failed.' : null,
    access_expires_at_ms: authState?.access_expires_at_ms || null
  };
}

async function getAuthStatePayload() {
  const authState = await getAuthState();
  const deviceSession = await getDeviceAuthSession();
  return authStatePayload(authState, deviceSession);
}

async function syncPendingAuthSession() {
  const session = await getDeviceAuthSession();
  if (!session || session.status !== 'pending') {
    return;
  }
  if (safeNumber(session.expires_at_ms, 0) <= Date.now()) {
    await setDeviceAuthSession({ ...session, status: 'failed', error: 'Sign-in request expired.' });
    return;
  }
  await pollDeviceAuthorization();
}

function scheduleAuthPolling(seconds) {
  if (authPollTimer) {
    clearTimeout(authPollTimer);
  }
  authPollTimer = setTimeout(() => {
    void pollDeviceAuthorization();
  }, Math.max(1, safeNumber(seconds, 5)) * 1000);
}

async function finalizeAuthorizedSession(payload) {
  const authState = {
    access_token: payload.access_token,
    access_expires_at_ms: Date.now() + safeNumber(payload.access_token_expires_in, 0) * 1000,
    refresh_token: payload.refresh_token,
    refresh_expires_at_ms: Date.now() + safeNumber(payload.refresh_token_expires_in, 0) * 1000
  };
  await setAuthState(authState);
  await clearDeviceAuthSession();
  if (authPollTimer) {
    clearTimeout(authPollTimer);
    authPollTimer = null;
  }
  await triggerActiveTabExtraction();
}

async function pollDeviceAuthorization() {
  const session = await getDeviceAuthSession();
  if (!session) {
    return;
  }

  if (Date.now() >= safeNumber(session.expires_at_ms, 0)) {
    await setDeviceAuthSession({ ...session, status: 'failed', error: 'Sign-in request expired.' });
    return;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  let response;
  let payload = {};

  try {
    response = await fetch(`${config.apiBaseUrl}/api/auth/device/poll`, {
      method: 'POST',
      headers: buildHeaders('', true),
      body: JSON.stringify({
        device_code: session.device_code,
        install_hash: installHash
      })
    });
  } catch (_error) {
    scheduleAuthPolling(session.interval_seconds || 5);
    return;
  }

  try {
    payload = await response.json();
  } catch (_error) {
    payload = {};
  }

  if (response.ok && payload?.access_token && payload?.refresh_token) {
    await finalizeAuthorizedSession(payload);
    return;
  }

  const errorCode = String(payload?.error || '');
  if (response.status === 428 || errorCode === 'authorization_pending') {
    scheduleAuthPolling(session.interval_seconds || 5);
    return;
  }

  const errorMessage = response.status >= 500
    ? `Authorization service unavailable (${response.status}).`
    : (payload?.detail || `Authorization was not completed (${response.status}).`);
  await setDeviceAuthSession({
    ...session,
    status: 'failed',
    error: errorMessage
  });
}

async function startDeviceAuthorization(interactive = true) {
  const existing = await getDeviceAuthSession();
  if (existing && existing.status === 'pending' && existing.expires_at_ms > Date.now()) {
    if (interactive) {
      await chrome.tabs.create({ url: existing.verification_uri_complete });
    }
    scheduleAuthPolling(existing.interval_seconds || 5);
    return existing;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  const extensionVersion = chrome.runtime.getManifest().version;

  const response = await fetch(`${config.apiBaseUrl}/api/auth/device/start`, {
    method: 'POST',
    headers: buildHeaders('', true),
    body: JSON.stringify({
      install_hash: installHash,
      extension_version: extensionVersion
    })
  });

  if (!response.ok) {
    throw new Error(`Could not start sign-in flow (${response.status}).`);
  }

  const payload = await response.json();
  const nextSession = {
    device_code: payload.device_code,
    user_code: payload.user_code,
    verification_uri_complete: payload.verification_uri_complete,
    interval_seconds: safeNumber(payload.interval, 5),
    expires_at_ms: Date.now() + safeNumber(payload.expires_in, 0) * 1000,
    status: 'pending',
    error: ''
  };

  await setDeviceAuthSession(nextSession);
  if (interactive) {
    await chrome.tabs.create({ url: payload.verification_uri_complete });
  }
  scheduleAuthPolling(nextSession.interval_seconds);
  return nextSession;
}

async function refreshAccessToken(config, installHash, authState) {
  if (!authState?.refresh_token || safeNumber(authState.refresh_expires_at_ms, 0) <= Date.now()) {
    return '';
  }

  const response = await fetch(`${config.apiBaseUrl}/api/auth/token/refresh`, {
    method: 'POST',
    headers: buildHeaders('', true),
    body: JSON.stringify({
      refresh_token: authState.refresh_token,
      install_hash: installHash
    })
  });

  if (!response.ok) {
    await clearAuthState();
    return '';
  }

  const payload = await response.json();
  const nextState = {
    access_token: payload.access_token,
    access_expires_at_ms: Date.now() + safeNumber(payload.access_token_expires_in, 0) * 1000,
    refresh_token: payload.refresh_token,
    refresh_expires_at_ms: Date.now() + safeNumber(payload.refresh_token_expires_in, 0) * 1000
  };
  await setAuthState(nextState);
  return nextState.access_token;
}

async function ensureAccessToken({ interactive = false } = {}) {
  const authState = await getAuthState();
  if (authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms)) {
    return authState.access_token;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  const refreshed = await refreshAccessToken(config, installHash, authState);
  if (refreshed) {
    return refreshed;
  }

  if (interactive) {
    await startDeviceAuthorization(true);
  }
  return '';
}

async function postSeenTelemetry(domain, installHash, accessToken, config) {
  try {
    await fetch(`${config.apiBaseUrl}/api/telemetry/seen`, {
      method: 'POST',
      headers: buildHeaders(accessToken, true),
      body: JSON.stringify({
        domain,
        user_install_hash: installHash
      })
    });
  } catch (_error) {
    // Telemetry is best-effort and should not block scans.
  }
}

async function requestScan(domain, signals) {
  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  let accessToken = await ensureAccessToken({ interactive: false });
  if (!accessToken) {
    throw createAuthRequiredError();
  }

  await postSeenTelemetry(domain, installHash, accessToken, config);

  const extensionVersion = chrome.runtime.getManifest().version;
  const requestBody = {
    domain,
    extracted_signals: signals,
    extension_version: extensionVersion,
    user_install_hash: installHash,
    triggered_by: 'USER_VISIT',
    include_checks: false,
    include_evidence: false
  };

  let response = await fetch(`${config.apiBaseUrl}/api/scan`, {
    method: 'POST',
    headers: buildHeaders(accessToken, true),
    body: JSON.stringify(requestBody)
  });

  if (response.status === 401 || response.status === 403) {
    const authState = await getAuthState();
    accessToken = await refreshAccessToken(config, installHash, authState);
    if (!accessToken) {
      throw createAuthRequiredError();
    }
    response = await fetch(`${config.apiBaseUrl}/api/scan`, {
      method: 'POST',
      headers: buildHeaders(accessToken, true),
      body: JSON.stringify(requestBody)
    });
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw createAuthRequiredError();
    }
    throw new Error(`Scan API failed (${response.status}).`);
  }

  return sanitizeSummaryResult(await response.json());
}

function canUseCacheEntry(cachedEntry, htmlHash, ttlMs, now) {
  if (!cachedEntry?.timestamp || !cachedEntry?.summary) {
    return false;
  }
  if (now - cachedEntry.timestamp >= ttlMs) {
    return false;
  }
  if (cachedEntry.html_hash && htmlHash && cachedEntry.html_hash !== htmlHash) {
    return false;
  }
  return true;
}

async function resolveDomainSummary(tabId, domain, signals) {
  const now = Date.now();
  const { cacheTtlHours } = await getExtensionConfig();
  const ttlMs = cacheTtlHours * 60 * 60 * 1000;
  const htmlHash = signals?.html_hash || null;
  const cache = await getCache();
  const cachedEntry = cache[domain];

  if (canUseCacheEntry(cachedEntry, htmlHash, ttlMs, now)) {
    const cachedResult = withResultMetadata(cachedEntry.summary, true, false);
    await setBadge(tabId, cachedResult);
    return cachedResult;
  }

  try {
    const freshSummary = await requestScan(domain, signals);
    const freshResult = withResultMetadata(freshSummary, false, false);

    cache[domain] = {
      timestamp: now,
      html_hash: htmlHash,
      summary: freshSummary
    };
    await setCache(cache);
    await setBadge(tabId, freshResult);
    return freshResult;
  } catch (error) {
    if (cachedEntry?.summary) {
      const staleResult = withResultMetadata(cachedEntry.summary, true, true);
      await setBadge(tabId, staleResult);
      return staleResult;
    }
    throw error;
  }
}

async function getActiveTabDomain() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || typeof tab.id !== 'number') {
    return '';
  }
  const tabDomains = await getTabDomains();
  return tabDomains[String(tab.id)] || normalizeDomain(tab.url || '');
}

async function getSummaryForDomain(domain) {
  const cache = await getCache();
  const entry = cache[domain];
  if (!entry?.summary) {
    return null;
  }
  return withResultMetadata(entry.summary, false, false);
}

function sanitizeDetailedChecks(latestScan) {
  const checks = Array.isArray(latestScan?.check_results) ? latestScan.check_results : [];
  return checks.map((check) => ({
    check_name: String(check?.check_name || 'Unknown'),
    risk_points: safeNumber(check?.risk_points, 0),
    confidence: safeNumber(check?.confidence, 0),
    severity: String(check?.severity || 'INFO'),
    explanation: String(check?.explanation || 'No explanation available.')
  }));
}

async function fetchDetailedResultForDomain(domain) {
  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  let accessToken = await ensureAccessToken({ interactive: false });
  if (!accessToken) {
    throw createAuthRequiredError();
  }

  let response = await fetch(`${config.apiBaseUrl}/api/site/${encodeURIComponent(domain)}`, {
    method: 'GET',
    headers: buildHeaders(accessToken, false)
  });

  if (response.status === 401 || response.status === 403) {
    const authState = await getAuthState();
    accessToken = await refreshAccessToken(config, installHash, authState);
    if (!accessToken) {
      throw createAuthRequiredError();
    }
    response = await fetch(`${config.apiBaseUrl}/api/site/${encodeURIComponent(domain)}`, {
      method: 'GET',
      headers: buildHeaders(accessToken, false)
    });
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw createAuthRequiredError();
    }
    throw new Error(`Details lookup failed (${response.status}).`);
  }

  const payload = await response.json();
  return {
    domain,
    last_scanned_at: payload?.last_scanned_at || null,
    checks: sanitizeDetailedChecks(payload?.latest_scan)
  };
}

async function signOutCurrentInstall() {
  const config = await getExtensionConfig();
  const authState = await getAuthState();
  if (authState?.access_token) {
    try {
      await fetch(`${config.apiBaseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: buildHeaders(authState.access_token, true),
        body: JSON.stringify({})
      });
    } catch (_error) {
      // Continue local sign-out even if server cannot be reached.
    }
  }

  await clearAuthState();
  await clearDeviceAuthSession();
  return getAuthStatePayload();
}

chrome.runtime.onInstalled.addListener(async () => {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  const defaults = {};
  if (!syncData.api_base_url) {
    defaults.api_base_url = DEFAULT_API_BASE_URL;
  }
  if (!syncData.cache_ttl_hours) {
    defaults.cache_ttl_hours = DEFAULT_CACHE_TTL_HOURS;
  }
  if (Object.keys(defaults).length) {
    await storageSet('sync', defaults);
  }

  // Remove deprecated keys from older extension versions.
  await storageRemove('local', ['api_token', 'latest_results']);

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

        const domain = normalizeDomain(message.payload?.domain || sender.tab?.url || '');
        if (!domain) {
          sendResponse({ ok: false, error: 'Could not resolve domain.' });
          return;
        }

        const tabDomains = await getTabDomains();
        tabDomains[String(tabId)] = domain;
        await setTabDomains(tabDomains);

        const summary = await resolveDomainSummary(tabId, domain, message.payload?.signals || {});
        sendResponse({ ok: true, domain, result: summary, auth: await getAuthStatePayload() });
      } catch (error) {
        if (error?.code === 'auth_required') {
          sendResponse({
            ok: false,
            auth_required: true,
            error: 'Sign in required before scans can run.',
            auth: await getAuthStatePayload()
          });
          return;
        }
        sendResponse({ ok: false, error: error.message || 'Scan failed.' });
      } finally {
        await cleanupExpiredCache();
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
        const domain = await getActiveTabDomain();
        if (!domain) {
          sendResponse({ ok: false, error: 'No domain found for this tab.', auth: await getAuthStatePayload() });
          return;
        }

        const summary = await getSummaryForDomain(domain);
        if (!summary) {
          sendResponse({ ok: false, error: 'No scan result found yet for this tab.', auth: await getAuthStatePayload() });
          return;
        }

        sendResponse({ ok: true, domain, result: summary, auth: await getAuthStatePayload() });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Unable to load tab result.', auth: await getAuthStatePayload() });
      }
    })();
    return true;
  }

  if (message?.type === 'GET_DETAILED_RESULT_FOR_ACTIVE_TAB') {
    (async () => {
      try {
        const domain = await getActiveTabDomain();
        if (!domain) {
          sendResponse({ ok: false, error: 'No domain found for this tab.' });
          return;
        }
        const details = await fetchDetailedResultForDomain(domain);
        sendResponse({ ok: true, ...details, auth: await getAuthStatePayload() });
      } catch (error) {
        if (error?.code === 'auth_required') {
          sendResponse({
            ok: false,
            auth_required: true,
            error: 'Sign in required before loading details.',
            auth: await getAuthStatePayload()
          });
          return;
        }
        sendResponse({ ok: false, error: error.message || 'Unable to load detailed checks.' });
      }
    })();
    return true;
  }

  if (message?.type === 'GET_EXTENSION_CONFIG') {
    (async () => {
      const config = await getExtensionConfig();
      sendResponse({
        ok: true,
        config,
        install_hash: await ensureInstallHash(),
        auth: await getAuthStatePayload()
      });
    })();
    return true;
  }

  if (message?.type === 'GET_AUTH_STATE') {
    (async () => {
      await syncPendingAuthSession();
      sendResponse({ ok: true, auth: await getAuthStatePayload() });
    })();
    return true;
  }

  if (message?.type === 'BEGIN_AUTH_FLOW') {
    (async () => {
      try {
        await startDeviceAuthorization(true);
        sendResponse({ ok: true, auth: await getAuthStatePayload() });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Could not start sign-in.', auth: await getAuthStatePayload() });
      }
    })();
    return true;
  }

  if (message?.type === 'SIGN_OUT') {
    (async () => {
      const auth = await signOutCurrentInstall();
      sendResponse({ ok: true, auth });
    })();
    return true;
  }

  if (message?.type === 'CLEAR_EXTENSION_CACHE') {
    (async () => {
      await storageRemove('local', [STORAGE_KEYS.CACHE]);
      sendResponse({ ok: true });
    })();
    return true;
  }

  return false;
});

(async () => {
  const existingSession = await getDeviceAuthSession();
  if (existingSession && existingSession.status === 'pending' && existingSession.expires_at_ms > Date.now()) {
    scheduleAuthPolling(1);
  }
})();
