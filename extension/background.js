try {
  importScripts('runtime_config.js');
} catch (_error) {
  // Optional runtime config file; fall back to built-in defaults.
}

const RUNTIME_CONFIG = globalThis.SAFESPEND_RUNTIME_CONFIG || {};
const PACKAGED_API_BASE_URL = String(RUNTIME_CONFIG.API_BASE_URL || '').trim().replace(/\/$/, '');
const DEFAULT_API_BASE_URL = PACKAGED_API_BASE_URL || 'http://localhost:8000';
const DEFAULT_CACHE_TTL_HOURS = 24;

const STORAGE_KEYS = {
  CACHE: 'scan_cache',
  TAB_DOMAINS: 'tab_domains',
  TAB_STATES: 'tab_states',
  INSTALL_HASH: 'install_hash',
  CACHE_CLEANUP_AT: 'last_cache_cleanup_at',
  AUTH_STATE: 'auth_state',
  DEVICE_AUTH: 'device_auth_session',
  ALERT_STATE: 'alert_state',
  AUTH_PROFILE: 'auth_profile',
  TAB_EVENT_LOG: 'tab_event_log'
};

const CLOCK_SKEW_MS = 45 * 1000;
const CACHE_CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;

let authPollTimer = null;
let authPollInFlight = false;
let silentRefreshPromise = null;
let lastSilentRefreshAttemptAtMs = 0;
const activeScansByTab = new Map();
const activeScansByDomain = new Map();
const inFlightScanRequests = new Map();
const privateResultsByTab = new Map();
const pendingUnsupportedTimersByTab = new Map();
let lastAuthHintPollAtMs = 0;
const ALERT_DEDUP_WINDOW_MS = 5 * 60 * 1000;
const RISK_TOAST_MIN_SCORE = 25;
const NOT_SUPPORTED_DEBOUNCE_MS = 1400;
const DETECTING_STATE_TIMEOUT_MS = 4500;
const SCANNABLE_STALE_MS = 5000;
const SCANNABLE_RETRY_INTERVAL_MS = 12000;
const DETECTING_MAX_RETRIES = 2;

async function broadcastAuthStateUpdated() {
  try {
    await chrome.runtime.sendMessage({ type: 'AUTH_STATE_UPDATED' });
  } catch (_error) {
    // Ignore if no extension page listeners are active.
  }
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

function authOwnerKey(authState) {
  const token = String(authState?.access_token || '');
  if (!token) {
    return '';
  }
  return token.slice(-24);
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

function riskLabelFromTrust(trustLevel) {
  if (trustLevel === 'HIGH') return 'Low Risk';
  if (trustLevel === 'MEDIUM') return 'Medium Risk';
  return 'High Risk';
}

function clearPendingUnsupportedTimer(tabId) {
  const key = String(tabId);
  const timer = pendingUnsupportedTimersByTab.get(key);
  if (timer) {
    clearTimeout(timer);
    pendingUnsupportedTimersByTab.delete(key);
  }
}

function sanitizeReason(value) {
  return {
    check_name: String(value?.check_name || 'Unknown check'),
    risk_points: safeNumber(value?.risk_points, 0),
    severity: String(value?.severity || 'INFO'),
    explanation: String(value?.explanation || 'No explanation available.')
  };
}

function sanitizeSummaryResult(payload, options = {}) {
  const includeChecks = Boolean(options?.includeChecks);
  const sanitized = {
    risk_score: safeNumber(payload?.risk_score, 0),
    trust_level: String(payload?.trust_level || 'MEDIUM'),
    score_confidence: safeNumber(payload?.score_confidence, 0),
    last_scanned_at: payload?.last_scanned_at || null,
    disclaimer: payload?.disclaimer || 'Risk score is informational only.',
    top_reasons: Array.isArray(payload?.top_reasons) ? payload.top_reasons.slice(0, 3).map(sanitizeReason) : [],
    top_reductions: Array.isArray(payload?.top_reductions) ? payload.top_reductions.slice(0, 3).map(sanitizeReason) : []
  };
  if (includeChecks) {
    sanitized.checks = sanitizeDetailedChecks({ check_results: payload?.checks || [] });
  }
  return sanitized;
}

function withResultMetadata(result, fromCache, staleCache = false) {
  return {
    ...result,
    from_cache: fromCache,
    stale_cache: staleCache
  };
}

async function getExtensionConfig() {
  const syncData = await storageGet('sync', ['api_base_url_override', 'api_base_url', 'cache_ttl_hours']);
  const overrideValue = String(syncData.api_base_url_override || '').trim().replace(/\/$/, '');
  const legacyValue = String(syncData.api_base_url || '').trim().replace(/\/$/, '');
  const apiBaseUrl = overrideValue || legacyValue || DEFAULT_API_BASE_URL;
  return {
    apiBaseUrl,
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

async function getTabStates() {
  const localData = await storageGet('local', [STORAGE_KEYS.TAB_STATES]);
  return localData[STORAGE_KEYS.TAB_STATES] || {};
}

async function setTabStates(tabStates) {
  await storageSet('local', { [STORAGE_KEYS.TAB_STATES]: tabStates });
}

async function getTabEventLog() {
  const localData = await storageGet('local', [STORAGE_KEYS.TAB_EVENT_LOG]);
  return localData[STORAGE_KEYS.TAB_EVENT_LOG] || {};
}

async function setTabEventLog(logValue) {
  await storageSet('local', { [STORAGE_KEYS.TAB_EVENT_LOG]: logValue });
}

async function appendTabEvent(tabId, domain, event, details = {}) {
  if (typeof tabId !== 'number') {
    return;
  }
  const key = `${String(tabId)}::${normalizeDomain(domain || '')}`;
  const logs = await getTabEventLog();
  const entries = Array.isArray(logs[key]) ? logs[key] : [];
  entries.push({
    at_ms: Date.now(),
    event: String(event || 'unknown'),
    details: details && typeof details === 'object' ? details : {},
  });
  logs[key] = entries.slice(-30);
  await setTabEventLog(logs);
}

async function setTabStateWithEvent(tabId, domain, patch, event, eventDetails = {}) {
  const tabStates = await getTabStates();
  const key = String(tabId);
  const previous = tabStates[key] || {};
  const nextRevision = safeNumber(previous.state_revision, 0) + 1;
  tabStates[key] = {
    ...previous,
    ...patch,
    state_revision: nextRevision,
    last_event: String(event || ''),
    last_event_at_ms: Date.now(),
    updated_at_ms: Date.now(),
  };
  await setTabStates(tabStates);
  await appendTabEvent(tabId, domain, event, {
    state_revision: nextRevision,
    ...eventDetails,
  });
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

async function getAuthProfile() {
  const localData = await storageGet('local', [STORAGE_KEYS.AUTH_PROFILE]);
  return localData[STORAGE_KEYS.AUTH_PROFILE] || null;
}

async function setAuthProfile(profile) {
  await storageSet('local', { [STORAGE_KEYS.AUTH_PROFILE]: profile });
}

async function clearAuthProfile() {
  await storageRemove('local', [STORAGE_KEYS.AUTH_PROFILE]);
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
  const score = safeNumber(result?.risk_score, 0);
  const trust = String(result?.trust_level || 'LOW');
  const style = trustBadgeStyle(trust);
  const badgeText = trust === 'HIGH' ? 'L' : trust === 'MEDIUM' ? 'M' : 'H';
  const riskLabel = riskLabelFromTrust(trust);
  const title = `SafeSpend: ${riskLabel} (${score}/100)`;
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
    await chrome.action.setBadgeText({ tabId, text: badgeText });
    if (chrome.action.setBadgeTextColor) {
      await chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
    }
    await chrome.action.setTitle({ tabId, title });
  } catch (_error) {
    // Ignore badge/icon errors for tabs that no longer exist.
  }
}

async function setTransientBadge(tabId, state) {
  if (typeof tabId !== 'number') {
    return;
  }

  if (state === 'scanning') {
    try {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#1d9bf0' });
      await chrome.action.setBadgeText({ tabId, text: '...' });
      if (chrome.action.setBadgeTextColor) {
        await chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
      }
      await chrome.action.setTitle({ tabId, title: 'SafeSpend: Scan in progress' });
    } catch (_error) {
      // Ignore badge/icon errors for tabs that no longer exist.
    }
    return;
  }

  if (state === 'unsupported') {
    try {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });
      await chrome.action.setBadgeText({ tabId, text: 'NA' });
      if (chrome.action.setBadgeTextColor) {
        await chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
      }
      await chrome.action.setTitle({ tabId, title: 'SafeSpend: Unsupported page category' });
    } catch (_error) {
      // Ignore badge/icon errors for tabs that no longer exist.
    }
    return;
  }

  if (state === 'no_result') {
    try {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });
      await chrome.action.setBadgeText({ tabId, text: '?' });
      if (chrome.action.setBadgeTextColor) {
        await chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
      }
      await chrome.action.setTitle({ tabId, title: 'SafeSpend: No scan result yet' });
    } catch (_error) {
      // Ignore badge/icon errors for tabs that no longer exist.
    }
  }
}

async function clearBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ tabId, text: '' });
    await chrome.action.setTitle({ tabId, title: 'SafeSpend' });
  } catch (_error) {
    // Ignore badge/icon errors for tabs that no longer exist.
  }
}

async function clearTabState(tabId) {
  const tabDomains = await getTabDomains();
  const tabStates = await getTabStates();
  delete tabDomains[String(tabId)];
  delete tabStates[String(tabId)];
  await setTabDomains(tabDomains);
  await setTabStates(tabStates);
  const logs = await getTabEventLog();
  const prefix = `${String(tabId)}::`;
  const nextLogs = Object.fromEntries(Object.entries(logs).filter(([key]) => !key.startsWith(prefix)));
  await setTabEventLog(nextLogs);
  clearScanInProgress(tabId);
  privateResultsByTab.delete(String(tabId));
  clearPendingUnsupportedTimer(tabId);
  await clearBadge(tabId);
}

function domainScanKey(domain, mode = 'public') {
  return `${normalizeDomain(domain)}::${String(mode || 'public')}`;
}

function markScanInProgress(tabId, domain, mode = 'public') {
  const normalizedDomain = normalizeDomain(domain);
  const scanId = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  activeScansByTab.set(String(tabId), {
    domain: normalizedDomain,
    mode: String(mode || 'public'),
    started_at_ms: Date.now(),
    scan_id: scanId,
  });
  const key = domainScanKey(normalizedDomain, mode);
  const existing = activeScansByDomain.get(key);
  if (existing) {
    existing.tab_ids.add(String(tabId));
    activeScansByDomain.set(key, existing);
  } else {
    activeScansByDomain.set(key, {
      domain: normalizedDomain,
      mode: String(mode || 'public'),
      started_at_ms: Date.now(),
      tab_ids: new Set([String(tabId)]),
    });
  }
  return scanId;
}

function clearScanInProgress(tabId, expectedScanId = '') {
  const key = String(tabId);
  const current = activeScansByTab.get(key);
  if (!current) {
    return;
  }
  if (expectedScanId && String(current.scan_id || '') !== String(expectedScanId)) {
    return;
  }
  const domainKey = domainScanKey(current.domain, current.mode || 'public');
  const domainEntry = activeScansByDomain.get(domainKey);
  if (domainEntry) {
    domainEntry.tab_ids.delete(key);
    if (!domainEntry.tab_ids.size) {
      activeScansByDomain.delete(domainKey);
    } else {
      activeScansByDomain.set(domainKey, domainEntry);
    }
  }
  activeScansByTab.delete(key);
}

function getScanProgress(tabId, domain) {
  const normalizedDomain = normalizeDomain(domain || '');
  const entry = activeScansByTab.get(String(tabId));
  if (entry && (!normalizedDomain || entry.domain === normalizedDomain)) {
    return {
      domain: entry.domain,
      started_at_ms: entry.started_at_ms,
      elapsed_ms: Math.max(0, Date.now() - safeNumber(entry.started_at_ms, Date.now()))
    };
  }
  const domainEntry = activeScansByDomain.get(domainScanKey(normalizedDomain, 'public'));
  if (domainEntry) {
    return {
      domain: domainEntry.domain,
      started_at_ms: domainEntry.started_at_ms,
      elapsed_ms: Math.max(0, Date.now() - safeNumber(domainEntry.started_at_ms, Date.now()))
    };
  }
  return null;
}

function getOngoingScansSnapshot() {
  const now = Date.now();
  const rows = [];
  for (const entry of activeScansByDomain.values()) {
    const startedAt = safeNumber(entry?.started_at_ms, now);
    rows.push({
      domain: String(entry?.domain || ''),
      mode: String(entry?.mode || 'public'),
      started_at_ms: startedAt,
      elapsed_ms: Math.max(0, now - startedAt),
      tab_count: entry?.tab_ids instanceof Set ? entry.tab_ids.size : 0,
      tab_ids: entry?.tab_ids instanceof Set ? Array.from(entry.tab_ids).map((id) => Number(id)).filter(Number.isFinite) : [],
    });
  }
  rows.sort((a, b) => b.elapsed_ms - a.elapsed_ms);
  return rows;
}

async function triggerActiveTabExtraction() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== 'number') {
      return;
    }
    await setTransientBadge(tab.id, 'no_result');
    await triggerExtractionForTab(tab.id);
  } catch (_error) {
    // Best-effort refresh. Some tabs may not host content script.
  }
}

async function maybeTriggerCompatibilityExtraction(tabId) {
  if (typeof tabId !== 'number') {
    return;
  }
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  const tabDomains = await getTabDomains();
  const domain = tabDomains[String(tabId)] || normalizeDomain(tab?.url || '');
  if (domain) {
    const cachedSummary = await getSummaryForDomain(domain);
    if (cachedSummary) {
      const tabStates = await getTabStates();
      const state = tabStates[String(tabId)] || null;
      const kind = String(state?.kind || '');
      if (!state || kind === 'detecting' || kind === 'scan_error') {
        await setTabStateWithEvent(tabId, domain, {
          kind: 'scannable',
          detect_retry_count: 0,
          reason: '',
        }, 'activate_with_cached_summary');
      }
      return;
    }
  }
  const tabStates = await getTabStates();
  const state = tabStates[String(tabId)] || null;
  const kind = String(state?.kind || '');
  if (state && kind !== 'detecting') {
    return;
  }
  await triggerExtractionForTab(tabId);
}

async function triggerExtractionForTab(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'RUN_EXTRACTION' });
    return;
  } catch (_error) {
    // If the content script is missing (already-open tab, extension reloaded), inject and retry once.
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    await chrome.tabs.sendMessage(tabId, { type: 'RUN_EXTRACTION' });
  } catch (_error) {
    // Ignore pages where scripting cannot be injected (browser internals, restricted pages).
  }
}

async function requestContentSignals(tabId, { force = false } = {}) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_SIGNALS', force });
    if (response?.ok) {
      return response.payload || null;
    }
  } catch (_error) {
    // Content script may not be injected yet.
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    const response = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_SIGNALS', force });
    if (response?.ok) {
      return response.payload || null;
    }
  } catch (_error) {
    // Ignore pages where scripts cannot be injected.
  }

  return null;
}

function authStatePayload(authState, deviceSession, authProfile = null) {
  const now = Date.now();
  const accessFresh = Boolean(authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms));
  const refreshAvailable = Boolean(authState?.refresh_token && safeNumber(authState.refresh_expires_at_ms, 0) > now);
  const recovering = !accessFresh && refreshAvailable;
  const authenticated = accessFresh || recovering;
  const sessionPending = Boolean(deviceSession && deviceSession.status === 'pending' && deviceSession.expires_at_ms > now);

  return {
    authenticated,
    preview_mode: !authenticated,
    recovering,
    refresh_available: refreshAvailable,
    in_progress: sessionPending,
    verifying: sessionPending && authPollInFlight,
    user_code: sessionPending ? deviceSession.user_code : null,
    verification_url: sessionPending ? deviceSession.verification_uri_complete : null,
    user_email: String(authProfile?.user_email || ''),
    auth_error: deviceSession?.status === 'failed' ? deviceSession.error || 'Authorization failed.' : null,
    access_expires_at_ms: authState?.access_expires_at_ms || null
  };
}

async function refreshAuthProfile({ force = false } = {}) {
  const authState = await getAuthState();
  const authenticated = Boolean(authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms));
  if (!authenticated) {
    await clearAuthProfile();
    return null;
  }

  const existing = await getAuthProfile();
  const existingAgeMs = Date.now() - safeNumber(existing?.fetched_at_ms, 0);
  if (!force && existing?.user_email && existingAgeMs < 5 * 60 * 1000) {
    return existing;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  let accessToken = authState.access_token;
  if (!accessToken || !isFreshTimestamp(authState.access_expires_at_ms)) {
    accessToken = await refreshAccessToken(config, installHash, authState);
  }
  if (!accessToken) {
    await clearAuthProfile();
    return null;
  }

  try {
    const response = await fetch(`${config.apiBaseUrl}/api/auth/session`, {
      method: 'GET',
      headers: buildHeaders(accessToken, false),
    });
    if (!response.ok) {
      await clearAuthProfile();
      return null;
    }
    const payload = await response.json();
    const profile = {
      user_email: String(payload?.user || ''),
      fetched_at_ms: Date.now(),
    };
    await setAuthProfile(profile);
    return profile;
  } catch (_error) {
    return existing || null;
  }
}

async function getAuthStatePayload() {
  let authState = await getAuthState();
  await maybeTrySilentRefreshAuthState(authState);
  authState = await getAuthState();
  const deviceSession = await getDeviceAuthSession();
  const authProfile = await getAuthProfile();
  return authStatePayload(authState, deviceSession, authProfile);
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

async function setDeviceAuthSessionIfCurrent(currentDeviceCode, nextSession) {
  const latest = await getDeviceAuthSession();
  if (!latest || String(latest.device_code || '') !== String(currentDeviceCode || '')) {
    return false;
  }
  await setDeviceAuthSession(nextSession);
  return true;
}

function scheduleAuthPolling(seconds) {
  if (authPollTimer) {
    clearTimeout(authPollTimer);
  }
  authPollTimer = setTimeout(() => {
    void pollDeviceAuthorization();
  }, Math.max(1, safeNumber(seconds, 5)) * 1000);
}

async function pollDeviceAuthorizationFromHint() {
  const now = Date.now();
  if (now - lastAuthHintPollAtMs < 900) {
    return;
  }
  lastAuthHintPollAtMs = now;
  await pollDeviceAuthorization();
}

async function maybePollAfterVerifyTabUpdate(tabId, changeInfo, tab) {
  if (changeInfo.status !== 'complete') {
    return;
  }

  const session = await getDeviceAuthSession();
  if (!session || session.status !== 'pending' || safeNumber(session.expires_at_ms, 0) <= Date.now()) {
    return;
  }

  const config = await getExtensionConfig();
  const tabUrl = String(changeInfo.url || tab?.url || '');
  const expectedPrefix = `${config.apiBaseUrl}/auth/device/verify`;
  const sameTab = safeNumber(session.verification_tab_id, -1) === safeNumber(tabId, -2);
  const onVerifyPage = tabUrl.startsWith(expectedPrefix);

  if (onVerifyPage && !sameTab) {
    await setDeviceAuthSessionIfCurrent(session.device_code, {
      ...session,
      verification_tab_id: tabId,
    });
  }

  if (!sameTab && !onVerifyPage) {
    return;
  }

  await pollDeviceAuthorizationFromHint();
}

async function finalizeAuthorizedSession(payload, session = null) {
  const authState = {
    access_token: payload.access_token,
    access_expires_at_ms: Date.now() + safeNumber(payload.access_token_expires_in, 0) * 1000,
    refresh_token: payload.refresh_token,
    refresh_expires_at_ms: Date.now() + safeNumber(payload.refresh_token_expires_in, 0) * 1000
  };
  await setAuthState(authState);
  await clearDeviceAuthSession();
  await clearAuthProfile();
  await refreshAuthProfile({ force: true });
  await storageRemove('local', [STORAGE_KEYS.CACHE]);
  if (authPollTimer) {
    clearTimeout(authPollTimer);
    authPollTimer = null;
  }
  const verificationTabId = safeNumber(session?.verification_tab_id, -1);
  if (verificationTabId >= 0) {
    try {
      await chrome.tabs.remove(verificationTabId);
    } catch (_error) {
      // Ignore if tab was already closed by user.
    }
  } else {
    try {
      const config = await getExtensionConfig();
      const verifyTabs = await chrome.tabs.query({ url: `${config.apiBaseUrl}/auth/device/verify*` });
      for (const tab of verifyTabs) {
        if (typeof tab?.id === 'number') {
          await chrome.tabs.remove(tab.id);
        }
      }
    } catch (_error) {
      // Ignore if URL query pattern or tab closure fails in this browser.
    }
  }
  await broadcastAuthStateUpdated();
  try {
    const tabs = await chrome.tabs.query({});
    await Promise.all(
      tabs
        .filter((tab) => typeof tab?.id === 'number' && /^https?:/i.test(String(tab?.url || '')))
        .map((tab) => triggerExtractionForTab(tab.id))
    );
  } catch (_error) {
    // Best effort only.
  }
  await triggerActiveTabExtraction();
}

async function pollDeviceAuthorization() {
  const session = await getDeviceAuthSession();
  if (!session) {
    return;
  }

  if (Date.now() >= safeNumber(session.expires_at_ms, 0)) {
    await setDeviceAuthSessionIfCurrent(session.device_code, { ...session, status: 'failed', error: 'Sign-in request expired.' });
    return;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  let response;
  let payload = {};
  authPollInFlight = true;
  await broadcastAuthStateUpdated();

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
    authPollInFlight = false;
    await broadcastAuthStateUpdated();
    return;
  }

  try {
    payload = await response.json();
  } catch (_error) {
    payload = {};
  }

  if (response.ok && payload?.access_token && payload?.refresh_token) {
    await finalizeAuthorizedSession(payload, session);
    authPollInFlight = false;
    await broadcastAuthStateUpdated();
    return;
  }

  const errorCode = String(payload?.error || '');
  if (response.status === 428 || errorCode === 'authorization_pending') {
    scheduleAuthPolling(Math.min(session.interval_seconds || 5, 2));
    authPollInFlight = false;
    await broadcastAuthStateUpdated();
    return;
  }

  if (errorCode === 'authorization_consumed') {
    const authState = await getAuthState();
    const hasUsableSession = Boolean(
      (authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms))
      || (authState?.refresh_token && safeNumber(authState.refresh_expires_at_ms, 0) > Date.now())
    );
    if (hasUsableSession) {
      await clearDeviceAuthSession();
      if (authPollTimer) {
        clearTimeout(authPollTimer);
        authPollTimer = null;
      }
      const verificationTabId = safeNumber(session?.verification_tab_id, -1);
      if (verificationTabId >= 0) {
        try {
          await chrome.tabs.remove(verificationTabId);
        } catch (_error) {
          // Ignore if tab was already closed by user.
        }
      }
      authPollInFlight = false;
      await broadcastAuthStateUpdated();
      return;
    }
    await setDeviceAuthSessionIfCurrent(
      session.device_code,
      {
        ...session,
        status: 'failed',
        error: 'This sign-in code was already used. Start a new sign-in from this device.',
      }
    );
    authPollInFlight = false;
    await broadcastAuthStateUpdated();
    return;
  }

  const errorMessage = response.status >= 500
    ? `Authorization service unavailable (${response.status}).`
    : (payload?.detail || `Authorization was not completed (${response.status}).`);
  await setDeviceAuthSessionIfCurrent(session.device_code, {
    ...session,
    status: 'failed',
    error: errorMessage
  });
  authPollInFlight = false;
  await broadcastAuthStateUpdated();
}

async function startDeviceAuthorization(interactive = true) {
  const existing = await getDeviceAuthSession();
  if (existing && existing.status === 'pending' && existing.expires_at_ms > Date.now()) {
    if (interactive) {
      const tab = await chrome.tabs.create({ url: existing.verification_uri_complete });
      await setDeviceAuthSession({
        ...existing,
        verification_tab_id: tab?.id ?? null,
      });
    }
    scheduleAuthPolling(existing.interval_seconds || 5);
    return existing;
  }

  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  const extensionVersion = chrome.runtime.getManifest().version;

  let response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/auth/device/start`, {
      method: 'POST',
      headers: buildHeaders('', true),
      body: JSON.stringify({
        install_hash: installHash,
        extension_version: extensionVersion
      })
    });
  } catch (_error) {
    throw new Error(`Could not reach ${config.apiBaseUrl}. Check API URL/network and try again.`);
  }

  if (!response.ok) {
    throw new Error(`Could not start sign-in flow (${response.status}).`);
  }

  const payload = await response.json();
  const nextSession = {
    device_code: payload.device_code,
    user_code: payload.user_code,
    verification_uri_complete: payload.verification_uri_complete,
    verification_tab_id: null,
    interval_seconds: safeNumber(payload.interval, 5),
    expires_at_ms: Date.now() + safeNumber(payload.expires_in, 0) * 1000,
    status: 'pending',
    error: ''
  };

  let sessionToSave = nextSession;
  if (interactive) {
    const tab = await chrome.tabs.create({ url: payload.verification_uri_complete });
    sessionToSave = {
      ...nextSession,
      verification_tab_id: tab?.id ?? null,
    };
  }
  await setDeviceAuthSession(sessionToSave);
  await broadcastAuthStateUpdated();
  scheduleAuthPolling(nextSession.interval_seconds);
  return sessionToSave;
}

async function refreshAccessToken(config, installHash, authState) {
  if (!authState?.refresh_token || safeNumber(authState.refresh_expires_at_ms, 0) <= Date.now()) {
    return '';
  }

  let response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/auth/token/refresh`, {
      method: 'POST',
      headers: buildHeaders('', true),
      body: JSON.stringify({
        refresh_token: authState.refresh_token,
        install_hash: installHash
      })
    });
  } catch (_error) {
    // Network/transient failure: keep current auth state and retry later.
    return '';
  }

  if (!response.ok) {
    // Only clear local auth state on terminal token errors.
    if (response.status === 400 || response.status === 401 || response.status === 403) {
      await clearAuthState();
    }
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

async function maybeTrySilentRefreshAuthState(authState) {
  const now = Date.now();
  const accessFresh = Boolean(authState?.access_token && isFreshTimestamp(authState.access_expires_at_ms));
  const refreshAvailable = Boolean(authState?.refresh_token && safeNumber(authState.refresh_expires_at_ms, 0) > now);
  if (accessFresh || !refreshAvailable) {
    return;
  }
  if (silentRefreshPromise) {
    await silentRefreshPromise;
    return;
  }
  if (now - lastSilentRefreshAttemptAtMs < 12000) {
    return;
  }

  lastSilentRefreshAttemptAtMs = now;
  silentRefreshPromise = (async () => {
    const config = await getExtensionConfig();
    const installHash = await ensureInstallHash();
    await refreshAccessToken(config, installHash, authState);
  })().finally(() => {
    silentRefreshPromise = null;
  });

  await silentRefreshPromise;
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

async function submitFeedbackToBackend(payload = {}) {
  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  const extensionVersion = chrome.runtime.getManifest().version;
  const authProfile = await getAuthProfile();
  const userEmail = String(authProfile?.user_email || '').trim();
  const body = {
    category: String(payload?.category || '').trim(),
    message: String(payload?.message || '').trim(),
    domain: String(payload?.domain || '').trim(),
    contact_email: String(payload?.contact_email || '').trim() || userEmail,
    install_hash: installHash,
    extension_version: extensionVersion,
    source: 'extension_options',
  };
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    try {
      controller.abort();
    } catch (_error) {
      // ignore
    }
  }, 12000);
  let response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/feedback/submit`, {
      method: 'POST',
      headers: buildHeaders('', true),
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error('Feedback request timed out. Please try again.');
    }
    throw new Error(`Could not reach ${config.apiBaseUrl}. Check API URL/network and try again.`);
  } finally {
    clearTimeout(timeoutId);
  }
  if (!response.ok) {
    let detail = '';
    try {
      const payload = await response.json();
      detail = String(payload?.detail || payload?.error || '').trim();
    } catch (_error) {
      // ignore
    }
    throw new Error(
      detail
        ? `Could not submit feedback (${response.status}): ${detail}`
        : `Could not submit feedback (${response.status}).`
    );
  }
  return response.json().catch(() => ({ ok: true }));
}

async function requestScan(domain, signals, options = {}) {
  const config = await getExtensionConfig();
  const installHash = await ensureInstallHash();
  const forcePrivate = Boolean(options?.forcePrivate);
  const requireAuth = Boolean(options?.requireAuth || forcePrivate);
  const includeChecks = Boolean(options?.includeChecks);
  const includeEvidence = Boolean(options?.includeEvidence);
  const triggeredBy = forcePrivate ? 'MANUAL_LOOKUP' : (options?.triggeredBy || 'USER_VISIT');
  const skipTelemetry = Boolean(options?.skipTelemetry || forcePrivate);
  let accessToken = await ensureAccessToken({ interactive: false });
  if (!accessToken && !requireAuth) {
    return buildPreviewSummary(domain, signals);
  }

  if (!skipTelemetry && accessToken) {
    await postSeenTelemetry(domain, installHash, accessToken, config);
  }

  const extensionVersion = chrome.runtime.getManifest().version;
  const requestBody = {
    domain,
    extracted_signals: signals,
    extension_version: extensionVersion,
    user_install_hash: installHash,
    triggered_by: triggeredBy,
    include_checks: includeChecks,
    include_evidence: includeEvidence,
    force_private: forcePrivate
  };

  let response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/scan`, {
      method: 'POST',
      headers: buildHeaders(accessToken, true),
      body: JSON.stringify(requestBody)
    });
  } catch (_error) {
    if (requireAuth) {
      throw new Error(`Could not reach ${config.apiBaseUrl}. Check API URL/network and try again.`);
    }
    return buildPreviewSummary(domain, signals);
  }

  if (response.status === 401 || response.status === 403) {
    if (accessToken) {
      const authState = await getAuthState();
      accessToken = await refreshAccessToken(config, installHash, authState);
      if (!accessToken) {
        if (requireAuth) {
          throw createAuthRequiredError();
        }
        return buildPreviewSummary(domain, signals);
      }
      response = await fetch(`${config.apiBaseUrl}/api/scan`, {
        method: 'POST',
        headers: buildHeaders(accessToken, true),
        body: JSON.stringify(requestBody)
      });
    } else {
      if (requireAuth) {
        throw createAuthRequiredError();
      }
      return buildPreviewSummary(domain, signals);
    }
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('No indexed scan history is available for detailed checks yet.');
    }
    if (response.status === 401 || response.status === 403) {
      throw createAuthRequiredError();
    }
    throw new Error(`Scan API failed (${response.status}).`);
  }

  return sanitizeSummaryResult(await response.json(), { includeChecks });
}

function buildPreviewSummary(domain, signals) {
  const reasons = [];
  const reductions = [];
  let score = 0;
  const policies = signals?.policies || {};
  const contact = signals?.contact || {};
  const platform = String(signals?.platform || 'unknown').toLowerCase();

  if (!signals?.is_https) {
    score += 25;
    reasons.push({
      check_name: 'HTTPS Preview Check',
      risk_points: 25,
      severity: 'HIGH',
      explanation: 'Site is not using HTTPS.'
    });
  }

  const hasPolicy = Boolean(policies.refund || policies.privacy || policies.terms);
  if (!hasPolicy) {
    score += 18;
    reasons.push({
      check_name: 'Policy Preview Check',
      risk_points: 18,
      severity: 'WARNING',
      explanation: 'No clear policy pages detected from this page.'
    });
  }

  const hasContact = Boolean(contact.email || contact.phone || contact.contact_page || contact.address);
  if (!hasContact) {
    score += 16;
    reasons.push({
      check_name: 'Contact Preview Check',
      risk_points: 16,
      severity: 'WARNING',
      explanation: 'No obvious contact method detected from this page.'
    });
  }

  if (signals?.custom_checkout) {
    score += 12;
    reasons.push({
      check_name: 'Checkout Preview Check',
      risk_points: 12,
      severity: 'WARNING',
      explanation: 'Checkout appears to move to a different domain.'
    });
  }

  if (['shopify', 'woocommerce', 'magento', 'bigcommerce'].includes(platform)) {
    score = Math.max(0, score - 4);
    reductions.push({
      check_name: 'Platform Reputation Preview',
      risk_points: -4,
      severity: 'INFO',
      explanation: 'Known e-commerce platform signal lowered the preview risk score.'
    });
  }

  const trustLevel = score <= 20 ? 'HIGH' : score <= 50 ? 'MEDIUM' : 'LOW';
  return {
    risk_score: Math.max(0, Math.min(100, score)),
    trust_level: trustLevel,
    score_confidence: 0.45,
    last_scanned_at: new Date().toISOString(),
    disclaimer: 'Preview mode only: checks are incomplete and less reliable than full backend verification.',
    top_reasons: reasons.slice(0, 3),
    top_reductions: reductions.slice(0, 3),
    preview_mode: true,
    domain
  };
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
  const rapidNavCooldownMs = 2 * 60 * 1000;
  const htmlHash = signals?.html_hash || null;
  const cache = await getCache();
  const cachedEntry = cache[domain];
  const scanKey = domain;

  if (canUseCacheEntry(cachedEntry, htmlHash, ttlMs, now)) {
    const cachedResult = withResultMetadata(cachedEntry.summary, true, false);
    await setBadge(tabId, cachedResult);
    return cachedResult;
  }

  if (cachedEntry?.summary && cachedEntry?.timestamp && (now - cachedEntry.timestamp < rapidNavCooldownMs)) {
    const recentResult = withResultMetadata({
      ...cachedEntry.summary,
      cooldown_active: true,
      cooldown_remaining_ms: Math.max(0, rapidNavCooldownMs - (now - cachedEntry.timestamp)),
    }, true, false);
    await setBadge(tabId, recentResult);
    return recentResult;
  }

  try {
    let scanPromise = inFlightScanRequests.get(scanKey);
    if (!scanPromise) {
      scanPromise = requestScan(domain, signals).finally(() => {
        inFlightScanRequests.delete(scanKey);
      });
      inFlightScanRequests.set(scanKey, scanPromise);
    }

    const freshSummary = await scanPromise;
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

function setPrivateResultForTab(tabId, domain, result, ownerKey, checks = []) {
  privateResultsByTab.set(String(tabId), {
    domain: normalizeDomain(domain),
    owner_key: String(ownerKey || ''),
    result,
    checks: Array.isArray(checks) ? checks : [],
    last_scanned_at: result?.last_scanned_at || null,
  });
}

function clearPrivateResultForTab(tabId) {
  privateResultsByTab.delete(String(tabId));
}

function getPrivateResultForTab(tabId, domain, ownerKey) {
  const entry = privateResultsByTab.get(String(tabId));
  if (!entry) {
    return null;
  }
  if (entry.domain !== normalizeDomain(domain)) {
    return null;
  }
  if (!ownerKey || entry.owner_key !== ownerKey) {
    return null;
  }
  return entry || null;
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

async function notifyAndBadgeFromCachedSummary(tabId) {
  if (typeof tabId !== 'number') {
    return;
  }
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  const tabDomains = await getTabDomains();
  const domain = tabDomains[String(tabId)] || normalizeDomain(tab?.url || '');
  if (!domain) {
    return;
  }
  const summary = await getSummaryForDomain(domain);
  if (!summary) {
    return;
  }
  await setBadge(tabId, summary);
  await maybeNotifyHighRisk(tabId, domain, summary);
}

async function sendMessageWithContentRetry(tabId, message) {
  try {
    await chrome.tabs.sendMessage(tabId, message);
    return true;
  } catch (_error) {
    // Content script may not be loaded yet on this tab.
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    await chrome.tabs.sendMessage(tabId, message);
    return true;
  } catch (_error) {
    return false;
  }
}

async function getAlertState() {
  const localData = await storageGet('local', [STORAGE_KEYS.ALERT_STATE]);
  return localData[STORAGE_KEYS.ALERT_STATE] || {};
}

async function setAlertState(state) {
  await storageSet('local', { [STORAGE_KEYS.ALERT_STATE]: state });
}

async function clearAlertStateForTab(tabId) {
  if (typeof tabId !== 'number') {
    return;
  }
  const alertState = await getAlertState();
  const suffix = `::${String(tabId)}`;
  const nextState = Object.fromEntries(
    Object.entries(alertState).filter(([key]) => !key.endsWith(suffix))
  );
  await setAlertState(nextState);
}

async function maybeNotifyHighRisk(tabId, domain, result) {
  const score = safeNumber(result?.risk_score, 0);
  if (score < RISK_TOAST_MIN_SCORE) {
    return;
  }

  const now = Date.now();
  const alertState = await getAlertState();
  const bucket = score >= 61 ? 'high' : score >= 31 ? 'medium' : 'elevated';

  const topReasons = Array.isArray(result?.top_reasons) ? result.top_reasons : [];
  const significantReasons = topReasons
    .filter((item) => safeNumber(item?.risk_points, 0) >= 8)
    .slice(0, 5)
    .map((item) => String(item?.explanation || item?.check_name || '').trim())
    .filter(Boolean);
  const uniqueReasons = [...new Set(significantReasons)];
  const fallbackReason = 'Potential risk indicators were detected.';

  const payload = {
    domain,
    risk_score: score,
    trust_level: String(result?.trust_level || 'LOW'),
    risk_label: riskLabelFromTrust(String(result?.trust_level || 'LOW')),
    reasons: uniqueReasons.length ? uniqueReasons : [fallbackReason],
  };

  const candidateTabs = await chrome.tabs.query({});
  const matchingTabs = candidateTabs.filter((candidate) => {
    if (typeof candidate?.id !== 'number') return false;
    const candidateDomain = normalizeDomain(candidate?.url || '');
    return Boolean(candidateDomain) && candidateDomain === domain;
  });

  if (!matchingTabs.length && typeof tabId === 'number') {
    matchingTabs.push({ id: tabId });
  }

  let didUpdateState = false;
  for (const candidate of matchingTabs) {
    const targetTabId = Number(candidate?.id);
    if (!Number.isFinite(targetTabId)) {
      continue;
    }
    const alertKey = `${domain}::${String(targetTabId)}`;
    const entry = alertState[alertKey];
    const lastAt = typeof entry === 'object' ? safeNumber(entry.last_at, 0) : safeNumber(entry, 0);
    const lastBucket = typeof entry === 'object' ? String(entry.bucket || '') : '';
    if (now - lastAt < ALERT_DEDUP_WINDOW_MS && bucket === lastBucket) {
      continue;
    }
    const sent = await sendMessageWithContentRetry(targetTabId, {
      type: 'SHOW_RISK_TOAST',
      payload,
    });
    if (!sent) {
      continue;
    }
    alertState[alertKey] = {
      last_at: now,
      bucket,
    };
    didUpdateState = true;
  }

  if (didUpdateState) {
    await setAlertState(alertState);
  }
}

function sanitizeDetailedChecks(latestScan) {
  const checks = Array.isArray(latestScan?.check_results) ? latestScan.check_results : [];

  function sanitizeEvidence(value, depth = 0) {
    if (depth >= 4) {
      return '[truncated]';
    }
    if (value === null || typeof value === 'undefined') {
      return null;
    }
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    if (Array.isArray(value)) {
      return value.slice(0, 20).map((item) => sanitizeEvidence(item, depth + 1));
    }
    if (typeof value === 'object') {
      const entries = Object.entries(value).slice(0, 30);
      return Object.fromEntries(entries.map(([key, item]) => [key, sanitizeEvidence(item, depth + 1)]));
    }
    return String(value);
  }

  return checks.map((check) => ({
    check_name: String(check?.check_name || 'Unknown'),
    risk_points: safeNumber(check?.risk_points, 0),
    confidence: safeNumber(check?.confidence, 0),
    severity: String(check?.severity || 'INFO'),
    explanation: String(check?.explanation || 'No explanation available.'),
    evidence: sanitizeEvidence(check?.evidence || {}),
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
  await clearAuthProfile();
  await storageRemove('local', [STORAGE_KEYS.CACHE]);
  privateResultsByTab.clear();
  await broadcastAuthStateUpdated();
  return getAuthStatePayload();
}

async function openRegisterPage() {
  const config = await getExtensionConfig();
  await chrome.tabs.create({ url: `${config.apiBaseUrl}/auth/register` });
}

async function deleteCurrentAccount(confirmEmail) {
  const config = await getExtensionConfig();
  const authState = await getAuthState();
  if (!authState?.access_token) {
    throw new Error('Sign in required before deleting account.');
  }

  const response = await fetch(`${config.apiBaseUrl}/api/auth/account/delete`, {
    method: 'POST',
    headers: buildHeaders(authState.access_token, true),
    body: JSON.stringify({
      confirm_email: String(confirmEmail || '').trim(),
    })
  });

  if (!response.ok) {
    let detail = 'Could not delete account.';
    try {
      const payload = await response.json();
      detail = payload?.detail || detail;
    } catch (_error) {
      // ignore
    }
    throw new Error(detail);
  }

  await clearAuthState();
  await clearDeviceAuthSession();
  await clearAuthProfile();
  await storageRemove('local', [STORAGE_KEYS.CACHE]);
  privateResultsByTab.clear();
  await broadcastAuthStateUpdated();
  return getAuthStatePayload();
}

chrome.runtime.onInstalled.addListener(async () => {
  const syncData = await storageGet('sync', ['api_base_url_override', 'api_base_url', 'cache_ttl_hours']);
  const defaults = {};
  if (!syncData.api_base_url_override) {
    const legacyApiBase = String(syncData.api_base_url || '').trim().replace(/\/$/, '');
    defaults.api_base_url_override = legacyApiBase || DEFAULT_API_BASE_URL;
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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  void maybePollAfterVerifyTabUpdate(tabId, changeInfo, tab);
  if (changeInfo.status === 'loading') {
    void (async () => {
      await clearAlertStateForTab(tabId);
      clearPendingUnsupportedTimer(tabId);
      clearPrivateResultForTab(tabId);
      const tabDomains = await getTabDomains();
      tabDomains[String(tabId)] = normalizeDomain(tab?.url || '');
      await setTabStateWithEvent(tabId, tabDomains[String(tabId)], {
        kind: 'detecting',
        reason: 'Checking whether this page is a supported store...',
      }, 'tab_loading_detecting');
      await setTabDomains(tabDomains);
      await setTransientBadge(tabId, 'no_result');
    })();
  }
  if (changeInfo.status === 'complete') {
    void triggerExtractionForTab(tabId);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  void setTransientBadge(tabId, 'no_result');
  void notifyAndBadgeFromCachedSummary(tabId);
  void maybeTriggerCompatibilityExtraction(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'PAGE_SIGNALS') {
    (async () => {
      let scanId = '';
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
        clearPendingUnsupportedTimer(tabId);
        tabDomains[String(tabId)] = domain;
        await setTabStateWithEvent(tabId, domain, {
          kind: 'scannable',
          detect_retry_count: 0,
        }, 'page_signals_scannable');
        await setTabDomains(tabDomains);
        clearPrivateResultForTab(tabId);

        scanId = markScanInProgress(tabId, domain, 'public');
        await setTransientBadge(tabId, 'scanning');
        const summary = await resolveDomainSummary(tabId, domain, message.payload?.signals || {});
        await maybeNotifyHighRisk(tabId, domain, summary);
        sendResponse({ ok: true, domain, result: summary, auth: await getAuthStatePayload() });
      } catch (error) {
        if (typeof sender.tab?.id === 'number') {
          const tab = await chrome.tabs.get(sender.tab.id).catch(() => null);
          const errorDomain = normalizeDomain(tab?.url || sender.tab?.url || '');
          await setTabStateWithEvent(sender.tab.id, errorDomain, {
            kind: 'scan_error',
            reason: error?.message || 'Scan failed. Please retry.',
          }, 'page_signals_scan_error', {
            error: String(error?.message || 'Scan failed. Please retry.')
          });
        }
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
        if (typeof sender.tab?.id === 'number') {
          clearScanInProgress(sender.tab.id, scanId);
        }
        await cleanupExpiredCache();
      }
    })();
    return true;
  }

  if (message?.type === 'NOT_ECOMMERCE') {
    (async () => {
      const tabId = sender.tab?.id;
      if (typeof tabId === 'number') {
        clearPendingUnsupportedTimer(tabId);
        const timer = setTimeout(() => {
          void (async () => {
            try {
              const tabStates = await getTabStates();
              const currentState = tabStates[String(tabId)] || {};
              if (currentState.kind === 'scannable' || currentState.kind === 'force_checked') {
                return;
              }
              const tab = await chrome.tabs.get(tabId).catch(() => null);
              const resolvedDomain = normalizeDomain(tab?.url || '');
              const tabDomains = await getTabDomains();
              tabDomains[String(tabId)] = resolvedDomain;
              await setTabStateWithEvent(tabId, resolvedDomain, {
                kind: 'not_supported',
                reason: 'This page does not look like a supported online store page yet.',
              }, 'not_ecommerce_unsupported');
              await setTabDomains(tabDomains);
              await setTransientBadge(tabId, 'unsupported');
            } finally {
              pendingUnsupportedTimersByTab.delete(String(tabId));
            }
          })();
        }, NOT_SUPPORTED_DEBOUNCE_MS);
        pendingUnsupportedTimersByTab.set(String(tabId), timer);
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === 'GET_RESULT_FOR_ACTIVE_TAB') {
    (async () => {
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = typeof activeTab?.id === 'number' ? activeTab.id : null;
        let tabStates = await getTabStates();
        const authState = await getAuthState();
        const ownerKey = authOwnerKey(authState);
        const activeUrl = String(activeTab?.url || '');
        const activeProtocol = (() => {
          try {
            return new URL(activeUrl).protocol;
          } catch (_error) {
            return '';
          }
        })();
        const urlDomain = normalizeDomain(activeTab?.url || '');
        const domain = (await getActiveTabDomain()) || urlDomain;
        if (!domain) {
          const pageState = {
            kind: 'not_supported',
            reason: activeProtocol === 'http:' || activeProtocol === 'https:'
              ? 'This page type is not currently supported.'
              : 'This browser page cannot be scanned by SafeSpend.',
            updated_at_ms: Date.now(),
          };
          sendResponse({
            ok: false,
            error: 'No domain found for this tab.',
            domain: urlDomain || '',
            page_state: pageState,
            auth: await getAuthStatePayload()
          });
          return;
        }

        const summary = await getSummaryForDomain(domain);
        if (!summary) {
          const progress = tabId === null ? null : getScanProgress(tabId, domain);
          const privateEntry = tabId === null ? null : getPrivateResultForTab(tabId, domain, ownerKey);
          if (privateEntry?.result) {
            sendResponse({
              ok: true,
              domain,
              result: privateEntry.result,
              private_result: true,
              auth: await getAuthStatePayload()
            });
            return;
          }
          if (typeof tabId === 'number') {
            const tabKey = String(tabId);
            let currentState = tabStates[tabKey] || null;
            if (!currentState) {
              await setTabStateWithEvent(tabId, domain, {
                kind: 'detecting',
                reason: 'Checking whether this page is a supported store...',
              }, 'get_result_missing_state_detecting');
              tabStates = await getTabStates();
              currentState = tabStates[tabKey] || null;
            }
            const resolvedState = currentState || {};
            if (String(resolvedState.kind || '') === 'force_checked' && !privateEntry) {
              await setTabStateWithEvent(tabId, domain, {
                kind: 'not_supported',
                reason: 'No private scan result is currently available. Run a private manual check again.',
              }, 'force_checked_private_missing');
              tabStates = await getTabStates();
              currentState = tabStates[tabKey] || null;
            }
            currentState = tabStates[tabKey] || {};
            const isDetecting = String(currentState.kind || '') === 'detecting';
            const detectingAgeMs = Date.now() - safeNumber(currentState.updated_at_ms, 0);
            if (isDetecting && !progress && activeTab?.status === 'complete' && detectingAgeMs > DETECTING_STATE_TIMEOUT_MS) {
              const retryCount = safeNumber(currentState.detect_retry_count, 0);
              if (retryCount < DETECTING_MAX_RETRIES) {
                await setTabStateWithEvent(tabId, domain, {
                  ...currentState,
                  detect_retry_count: retryCount + 1,
                  last_retry_at_ms: Date.now(),
                }, 'detecting_retry', {
                  retry_count: retryCount + 1
                });
                tabStates = await getTabStates();
                currentState = tabStates[tabKey] || currentState;
                await triggerExtractionForTab(tabId);
              } else {
                await setTabStateWithEvent(tabId, domain, {
                  kind: 'not_supported',
                  reason: 'This page type is not currently supported.',
                }, 'detecting_exhausted_unsupported');
                tabStates = await getTabStates();
                currentState = tabStates[tabKey] || currentState;
              }
            }
            const stateForBadge = currentState || {};
            if (String(stateForBadge.kind || '') === 'not_supported') {
              await setTransientBadge(tabId, 'unsupported');
            } else {
              await setTransientBadge(tabId, progress ? 'scanning' : 'no_result');
            }
          }
          const pageState = tabId === null ? null : tabStates[String(tabId)] || null;
          const stateKind = String(pageState?.kind || '');
          if (typeof tabId === 'number' && stateKind === 'scannable' && !progress) {
            const stateAgeMs = Date.now() - safeNumber(pageState?.updated_at_ms, 0);
            const lastRetryAtMs = safeNumber(pageState?.last_retry_at_ms, 0);
            const retryDue = Date.now() - lastRetryAtMs >= SCANNABLE_RETRY_INTERVAL_MS;
            if (stateAgeMs >= SCANNABLE_STALE_MS && retryDue) {
              await setTabStateWithEvent(tabId, domain, {
                ...pageState,
                last_retry_at_ms: Date.now(),
              }, 'scannable_stale_retry');
              tabStates = await getTabStates();
              await triggerExtractionForTab(tabId);
            }
          }
          const noResultMessage = stateKind === 'detecting'
            ? 'Checking whether this page is a supported store.'
            : stateKind === 'scannable'
              ? (progress ? 'Scan is currently running for this site.' : 'Preparing scan for this site...')
              : stateKind === 'scan_error'
                ? (pageState?.reason || 'Scan failed. Please retry.')
              : (progress ? 'Scan is currently running for this site.' : 'This page type is not currently supported.');
          sendResponse({
            ok: false,
            error: noResultMessage,
            domain,
            scan_in_progress: Boolean(progress),
            scan_progress: progress,
            page_state: pageState,
            auth: await getAuthStatePayload()
          });
          return;
        }

        if (typeof tabId === 'number') {
          await setBadge(tabId, summary);
        }
        sendResponse({ ok: true, domain, result: summary, auth: await getAuthStatePayload() });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Unable to load tab result.', auth: await getAuthStatePayload() });
      }
    })();
    return true;
  }

  if (message?.type === 'FORCE_CHECK_ACTIVE_TAB') {
    (async () => {
      let activeTabId = null;
      let scanId = '';
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = activeTab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ ok: false, error: 'No active tab available.' });
          return;
        }
        activeTabId = tabId;

        const domain = normalizeDomain(activeTab?.url || '');
        if (!domain) {
          sendResponse({ ok: false, error: 'Could not resolve domain for this tab.' });
          return;
        }

        const accessToken = await ensureAccessToken({ interactive: false });
        if (!accessToken) {
          sendResponse({
            ok: false,
            auth_required: true,
            error: 'Sign in required before running force checks.',
            auth: await getAuthStatePayload()
          });
          return;
        }

        const extracted = await requestContentSignals(tabId, { force: true });
        const signals = extracted?.signals || {};

        scanId = markScanInProgress(tabId, domain, 'private');
        await setTransientBadge(tabId, 'scanning');
        const summary = await requestScan(domain, signals, {
          forcePrivate: true,
          requireAuth: true,
          includeChecks: true,
          includeEvidence: true,
          triggeredBy: 'MANUAL_LOOKUP',
          skipTelemetry: true,
        });

        const authState = await getAuthState();
        const privateChecks = Array.isArray(summary?.checks) ? summary.checks : [];
        const privateSummary = { ...summary };
        delete privateSummary.checks;
        setPrivateResultForTab(tabId, domain, privateSummary, authOwnerKey(authState), privateChecks);

        const tabDomains = await getTabDomains();
        tabDomains[String(tabId)] = domain;
        await setTabStateWithEvent(tabId, domain, {
          kind: 'force_checked',
        }, 'force_check_complete');
        await setTabDomains(tabDomains);
        await setBadge(tabId, privateSummary);

        sendResponse({ ok: true, domain, result: privateSummary, private_result: true, auth: await getAuthStatePayload() });
      } catch (error) {
        if (error?.code === 'auth_required') {
          sendResponse({
            ok: false,
            auth_required: true,
            error: 'Sign in required before running force checks.',
            auth: await getAuthStatePayload()
          });
          return;
        }
        sendResponse({ ok: false, error: error.message || 'Force check failed.', auth: await getAuthStatePayload() });
      } finally {
        if (typeof activeTabId === 'number') {
          clearScanInProgress(activeTabId, scanId);
        }
      }
    })();
    return true;
  }

  if (message?.type === 'SCAN_NOW_ACTIVE_TAB') {
    (async () => {
      let activeTabId = null;
      let scanId = '';
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = activeTab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ ok: false, error: 'No active tab available.' });
          return;
        }
        activeTabId = tabId;

        const domain = normalizeDomain(activeTab?.url || '');
        if (!domain) {
          sendResponse({ ok: false, error: 'Could not resolve domain for this tab.' });
          return;
        }

        const extracted = await requestContentSignals(tabId, { force: false });
        const signals = extracted?.signals || {};

        scanId = markScanInProgress(tabId, domain, 'public');
        await setTransientBadge(tabId, 'scanning');
        const summary = await requestScan(domain, signals, {
          forcePrivate: false,
          requireAuth: false,
          includeChecks: false,
          includeEvidence: false,
          triggeredBy: 'USER_VISIT',
          skipTelemetry: false,
        });

        const cache = await getCache();
        cache[domain] = {
          timestamp: Date.now(),
          html_hash: signals?.html_hash || null,
          summary,
        };
        await setCache(cache);

        await setTabStateWithEvent(tabId, domain, {
          kind: 'scannable',
        }, 'scan_now_complete');
        await setBadge(tabId, summary);
        await maybeNotifyHighRisk(tabId, domain, summary);

        sendResponse({ ok: true, domain, result: summary, auth: await getAuthStatePayload() });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Could not run scan now.', auth: await getAuthStatePayload() });
      } finally {
        if (typeof activeTabId === 'number') {
          clearScanInProgress(activeTabId, scanId);
        }
      }
    })();
    return true;
  }

  if (message?.type === 'GET_DETAILED_RESULT_FOR_ACTIVE_TAB') {
    (async () => {
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = typeof activeTab?.id === 'number' ? activeTab.id : null;
        const domain = await getActiveTabDomain();
        if (!domain) {
          sendResponse({ ok: false, error: 'No domain found for this tab.' });
          return;
        }
        if (typeof tabId === 'number') {
          const authState = await getAuthState();
          const privateEntry = getPrivateResultForTab(tabId, domain, authOwnerKey(authState));
          if (privateEntry && Array.isArray(privateEntry.checks) && privateEntry.checks.length) {
            sendResponse({
              ok: true,
              domain,
              last_scanned_at: privateEntry.last_scanned_at || null,
              checks: privateEntry.checks,
              private_result: true,
              auth: await getAuthStatePayload(),
            });
            return;
          }
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

  if (message?.type === 'OPEN_EXTENSION_POPUP') {
    (async () => {
      try {
        await chrome.action.openPopup();
        sendResponse({ ok: true });
      } catch (_error) {
        sendResponse({ ok: false, error: 'Could not open extension popup.' });
      }
    })();
    return true;
  }

  if (message?.type === 'GET_EXTENSION_CONFIG') {
    (async () => {
      const config = await getExtensionConfig();
      await refreshAuthProfile({ force: false });
      sendResponse({
        ok: true,
        config,
        install_hash: await ensureInstallHash(),
        auth: await getAuthStatePayload()
      });
    })();
    return true;
  }

  if (message?.type === 'SUBMIT_FEEDBACK') {
    (async () => {
      try {
        const result = await submitFeedbackToBackend(message?.payload || {});
        sendResponse({ ok: true, delivered: Boolean(result?.delivered) });
      } catch (error) {
        sendResponse({ ok: false, error: error?.message || 'Could not submit feedback.' });
      }
    })();
    return true;
  }

  if (message?.type === 'GET_AUTH_STATE') {
    (async () => {
      await syncPendingAuthSession();
      await refreshAuthProfile({ force: false });
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

  if (message?.type === 'OPEN_REGISTER_PAGE') {
    (async () => {
      try {
        await openRegisterPage();
        sendResponse({ ok: true });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Could not open registration page.' });
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

  if (message?.type === 'DELETE_ACCOUNT') {
    (async () => {
      try {
        const auth = await deleteCurrentAccount(message?.confirm_email);
        sendResponse({ ok: true, auth });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || 'Could not delete account.' });
      }
    })();
    return true;
  }

  if (message?.type === 'REFRESH_AUTH_PROFILE') {
    (async () => {
      const profile = await refreshAuthProfile({ force: true });
      sendResponse({ ok: true, profile, auth: await getAuthStatePayload() });
    })();
    return true;
  }

  if (message?.type === 'CLEAR_EXTENSION_CACHE') {
    (async () => {
      await storageRemove('local', [
        STORAGE_KEYS.CACHE,
        STORAGE_KEYS.TAB_STATES,
        STORAGE_KEYS.TAB_DOMAINS,
        STORAGE_KEYS.ALERT_STATE,
        STORAGE_KEYS.TAB_EVENT_LOG,
      ]);
      activeScansByTab.clear();
      activeScansByDomain.clear();
      privateResultsByTab.clear();
      pendingUnsupportedTimersByTab.forEach((timer) => clearTimeout(timer));
      pendingUnsupportedTimersByTab.clear();
      try {
        const tabs = await chrome.tabs.query({});
        await Promise.all(
          tabs
            .filter((tab) => typeof tab?.id === 'number')
            .map((tab) => chrome.tabs.sendMessage(tab.id, { type: 'CLEAR_RISK_TOAST_SESSION' }).catch(() => null))
        );
      } catch (_error) {
        // Best effort only.
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === 'GET_ONGOING_SCANS') {
    (async () => {
      sendResponse({
        ok: true,
        scans: getOngoingScansSnapshot(),
      });
    })();
    return true;
  }

  if (message?.type === 'RUN_ACTIVE_EXTRACTION') {
    (async () => {
      await triggerActiveTabExtraction();
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
