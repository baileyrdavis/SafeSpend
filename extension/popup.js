function byId(id) {
  return document.getElementById(id);
}

let lastResultContextKey = '';
let lastKnownAuth = null;

const LOCAL_DATE_TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
  hour12: true,
});

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return LOCAL_DATE_TIME_FORMATTER.format(date);
}

function formatConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '-';
  return `${Math.round(numeric * 100)}%`;
}

function trustColor(level) {
  if (level === 'HIGH') return '#22c55e';
  if (level === 'MEDIUM') return '#f59e0b';
  return '#ef4444';
}

function riskLabelFromTrust(level) {
  if (level === 'HIGH') return 'Low Risk';
  if (level === 'MEDIUM') return 'Medium Risk';
  return 'High Risk';
}

function siteKindFromTrust(level) {
  if (level === 'HIGH') return { kind: 'ok', label: 'Low Risk' };
  if (level === 'MEDIUM') return { kind: 'warn', label: 'Medium Risk' };
  return { kind: 'risk', label: 'High Risk' };
}

function setStatus(message, type = 'info') {
  const status = byId('status');
  const text = String(message || '').trim();
  if (!text) {
    status.className = 'status hidden';
    status.textContent = '';
    return;
  }
  status.className = `status ${type}`;
  status.textContent = text;
}

function setScanActivity(visible, message = 'Scanning this site now...') {
  const panel = byId('scanActivity');
  const label = byId('scanActivityLabel');
  if (!panel || !label) return;
  label.textContent = message;
  panel.classList.toggle('hidden', !visible);
}

function setSiteKind(kind, label) {
  const pill = byId('siteKindPill');
  pill.className = `pill ${kind}`;
  pill.textContent = label;
}

function setButtonLoading(button, loadingText, isLoading, restoreLabel = true) {
  if (!button) return;
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = button.textContent;
  }
  if (isLoading) {
    button.disabled = true;
    button.classList.add('loading');
    button.textContent = loadingText;
    return;
  }
  button.disabled = false;
  button.classList.remove('loading');
  if (restoreLabel) {
    button.textContent = button.dataset.defaultLabel;
  }
}

function setHideAdvancedButtonVisible(visible) {
  byId('hideAdvancedBtn').classList.toggle('hidden', !visible);
}

function collapseAdvancedDetails(clearDetails = false) {
  const advancedSection = byId('advancedSection');
  advancedSection.open = false;
  if (!clearDetails) {
    return;
  }
  const loadButton = byId('loadDetailsBtn');
  const detailsList = byId('detailsList');
  detailsList.classList.add('hidden');
  detailsList.innerHTML = '';
  loadButton.dataset.defaultLabel = 'Show Detailed Checks';
  loadButton.textContent = 'Show Detailed Checks';
  setHideAdvancedButtonVisible(false);
}

function buildResultContextKey(response) {
  const domain = String(response?.domain || '-');
  if (!response?.ok) {
    return `${domain}|no-result`;
  }
  const result = response?.result || {};
  return [
    domain,
    String(result?.last_scanned_at || ''),
    String(result?.risk_score ?? ''),
    String(result?.score_confidence ?? ''),
    String(result?.preview_mode ? 'preview' : 'full'),
  ].join('|');
}

function clearRenderedResult() {
  byId('summaryCard').classList.add('hidden');
  byId('reasonsCard').classList.add('hidden');
  byId('advancedSection').classList.add('hidden');
  byId('detailsList').classList.add('hidden');
  byId('detailsList').innerHTML = '';
  byId('reasonsList').innerHTML = '';
  byId('riskScore').textContent = '-';
  byId('trustLevel').textContent = '-';
  byId('trustHint').textContent = '-';
  byId('scoreConfidence').textContent = '-';
  byId('lastScannedAt').textContent = '-';
  byId('disclaimerText').textContent = 'Risk score is informational only.';
  byId('previewBanner').classList.add('hidden');
  byId('reputationBanner').classList.add('hidden');
  byId('reputationBanner').textContent = '';
  byId('verifiedBadgeWrap').classList.add('hidden');
  byId('verifiedBadgeBtn').title = '';
  byId('verifiedBadgeDetail').classList.add('hidden');
  byId('verifiedBadgeDetail').textContent = '';
  byId('cooldownBanner').classList.add('hidden');
  byId('scanNowRow').classList.add('hidden');
  byId('forceCheckCard').classList.add('hidden');
  byId('scoreChangePanel').classList.add('hidden');
  byId('scoreChangePanel').classList.remove('up', 'down');
  byId('scoreChangeHeadline').textContent = 'No previous scan baseline yet.';
  byId('scoreChangeList').classList.add('hidden');
  byId('scoreChangeList').innerHTML = '';
  collapseAdvancedDetails(true);
}

function resolveAuth(auth) {
  if (auth && typeof auth === 'object') {
    lastKnownAuth = auth;
    return auth;
  }
  return lastKnownAuth || null;
}

function renderAuthPanel(auth, pageState = null) {
  const panel = byId('authPanel');
  const authCopy = byId('authState');
  const connectBtn = byId('connectBtn');
  const registerBtn = byId('registerBtn');
  const isUnsupported = String(pageState?.kind || '') === 'not_supported';

  if (!auth) {
    // Keep the last rendered auth UI to avoid flicker during transient
    // background worker restarts or timing gaps.
    return;
  }

  if (auth.authenticated) {
    panel.classList.add('hidden');
    return;
  }

  panel.classList.remove('hidden');
  connectBtn.classList.remove('hidden');

  if (auth.in_progress) {
    authCopy.textContent = auth.verifying
      ? 'Sign-in in progress. Verifying account connection...'
      : (auth.user_code
          ? `Sign-in in progress. Continue with code ${auth.user_code}.`
          : 'Sign-in in progress. Continue in your browser.');
    connectBtn.textContent = 'Resume Sign In';
    registerBtn.classList.add('hidden');
    return;
  }

  authCopy.textContent = auth.auth_error
    ? `${auth.auth_error} You can still use preview checks.`
    : (
      isUnsupported
        ? 'This page type is unsupported. Sign in to run a private manual check.'
        : 'Using preview checks only. Sign in to unlock full backend checks, known-brand spoof detection, and account history.'
    );
  connectBtn.textContent = 'Connect SafeSpend';
  registerBtn.classList.remove('hidden');
}

function renderForceCheckCard(auth, pageState) {
  const card = byId('forceCheckCard');
  if (!card) return;
  const forceBtn = byId('forceCheckBtn');
  const copy = byId('forceCheckCopy');
  const isUnsupported = String(pageState?.kind || '') === 'not_supported';
  const isAuthenticated = Boolean(auth?.authenticated);
  const shouldShow = isUnsupported && isAuthenticated;
  if (isUnsupported && isAuthenticated) {
    copy.textContent = 'This page type is unsupported. Run a private manual check anyway.';
    forceBtn.classList.remove('hidden');
    forceBtn.disabled = false;
  }
  card.classList.toggle('hidden', !shouldShow);
}

function renderSummary(result, domain) {
  byId('siteDomain').textContent = domain || '-';
  const trustLevelValue = String(result?.trust_level || 'MEDIUM');
  const siteKind = siteKindFromTrust(trustLevelValue);
  setSiteKind(siteKind.kind, siteKind.label);
  byId('summaryCard').classList.remove('hidden');
  byId('reasonsCard').classList.remove('hidden');

  const previewMode = Boolean(result?.preview_mode);
  const cooldownActive = Boolean(result?.cooldown_active);
  byId('previewBanner').classList.toggle('hidden', !previewMode);
  byId('cooldownBanner').classList.toggle('hidden', !cooldownActive);
  byId('scanNowRow').classList.toggle('hidden', !cooldownActive);
  byId('advancedSection').classList.toggle('hidden', previewMode);
  if (previewMode) {
    collapseAdvancedDetails(true);
  }

  byId('riskScore').textContent = String(result?.risk_score ?? '-');
  const trustLevel = byId('trustLevel');
  trustLevel.textContent = riskLabelFromTrust(trustLevelValue);
  trustLevel.style.color = trustColor(trustLevelValue);
  byId('trustHint').textContent = `Risk level: ${riskLabelFromTrust(trustLevelValue)}`;

  byId('scoreConfidence').textContent = formatConfidence(result?.score_confidence);
  byId('lastScannedAt').textContent = formatDate(result?.last_scanned_at);
  byId('disclaimerText').textContent = result?.disclaimer || 'Risk score is informational only.';
  renderScoreChange(result?.score_change);
  renderTopReductions(result?.top_reductions);
  renderVerifiedCompanyBanner(result?.top_reductions);

  const reasonsList = byId('reasonsList');
  reasonsList.innerHTML = '';
  const topReasons = Array.isArray(result?.top_reasons) ? result.top_reasons : [];
  const topReductions = Array.isArray(result?.top_reductions) ? result.top_reductions : [];
  const signalItems = [
    ...topReasons.map((item) => ({ ...item, signal_kind: 'risk' })),
    ...topReductions.map((item) => ({ ...item, signal_kind: 'good' })),
  ];
  if (!signalItems.length) {
    const li = document.createElement('li');
    li.textContent = 'No major risk indicators were detected in the top checks.';
    reasonsList.appendChild(li);
  } else {
    signalItems.forEach((reason) => {
      const li = document.createElement('li');
      const chip = document.createElement('span');
      chip.className = `impact-chip ${reason.signal_kind === 'good' ? 'positive' : 'negative'}`;
      chip.textContent = reason.signal_kind === 'good' ? 'Good signal' : 'Risk signal';
      const title = document.createElement('strong');
      title.textContent = String(reason.check_name || 'Check');
      const copy = document.createElement('p');
      copy.className = 'detail-explanation';
      copy.textContent = String(reason.explanation || 'No explanation available.');
      li.appendChild(chip);
      li.appendChild(title);
      li.appendChild(copy);
      reasonsList.appendChild(li);
    });
  }

  setStatus(
    previewMode
      ? `Preview checks only for ${domain}. Sign in for full reliability.`
      : '',
    previewMode ? 'info' : 'ok'
  );
}

function formatDelta(points) {
  const numeric = Number(points);
  if (!Number.isFinite(numeric)) return '0';
  if (numeric > 0) return `+${numeric}`;
  return String(numeric);
}

function renderScoreChange(scoreChange) {
  const panel = byId('scoreChangePanel');
  const headline = byId('scoreChangeHeadline');
  const list = byId('scoreChangeList');
  panel.classList.add('hidden');
  panel.classList.remove('up', 'down');
  list.classList.add('hidden');
  list.innerHTML = '';

  if (!scoreChange || !scoreChange.has_previous_scan) {
    return;
  }

  const delta = Number(scoreChange.delta_points || 0);
  const previousScore = Number(scoreChange.previous_risk_score || 0);
  const previousAt = formatDate(scoreChange.previous_scanned_at);
  const direction = String(scoreChange.direction || 'same');
  if (direction === 'up' || delta > 0) {
    panel.classList.add('up');
    headline.textContent = `Risk increased ${formatDelta(delta)} points (from ${previousScore}) since ${previousAt}.`;
  } else if (direction === 'down' || delta < 0) {
    panel.classList.add('down');
    headline.textContent = `Risk decreased ${formatDelta(delta)} points (from ${previousScore}) since ${previousAt}.`;
  } else {
    headline.textContent = `Risk score unchanged since ${previousAt} (${previousScore}).`;
  }

  const topChanges = Array.isArray(scoreChange.top_check_deltas) ? scoreChange.top_check_deltas : [];
  if (topChanges.length) {
    topChanges.slice(0, 3).forEach((item) => {
      const li = document.createElement('li');
      li.className = 'score-change-item';
      const deltaText = formatDelta(item.delta_points);
      li.textContent = `${item.check_name}: ${deltaText} (${item.previous_points} -> ${item.current_points})`;
      list.appendChild(li);
    });
    list.classList.remove('hidden');
  }

  panel.classList.remove('hidden');
}

function renderTopReductions(topReductions) {
  const banner = byId('reputationBanner');
  const reductions = Array.isArray(topReductions)
    ? topReductions.filter((item) => Number(item?.risk_points) < 0)
    : [];
  if (!reductions.length) {
    banner.classList.add('hidden');
    banner.textContent = '';
    return;
  }

  const reducedBy = reductions.reduce((sum, item) => sum + Math.abs(Number(item?.risk_points) || 0), 0);
  const topReduction = reductions[0];
  const topName = String(topReduction?.check_name || 'Trusted indicators');
  banner.textContent = `${topName} and related trusted signals lowered this score by ${reducedBy} points.`;
  banner.classList.remove('hidden');
}

function renderVerifiedCompanyBanner(topReductions) {
  const wrap = byId('verifiedBadgeWrap');
  const badge = byId('verifiedBadgeBtn');
  const detail = byId('verifiedBadgeDetail');
  const reductions = Array.isArray(topReductions)
    ? topReductions.filter((item) => Number(item?.risk_points) < 0)
    : [];
  const brandReduction = reductions.find((item) => (
    String(item?.check_name || '').toLowerCase().includes('brand impersonation') &&
    String(item?.explanation || '').toLowerCase().includes('official')
  ));

  if (!brandReduction) {
    wrap.classList.add('hidden');
    badge.title = '';
    detail.classList.add('hidden');
    detail.textContent = '';
    return;
  }

  const explanation = String(brandReduction.explanation || 'Domain matches an official known-brand domain.');
  const points = Math.abs(Number(brandReduction?.risk_points) || 0);
  badge.title = explanation;
  detail.textContent = `${explanation} Score reduction: ${points} points.`;
  detail.classList.add('hidden');
  wrap.classList.remove('hidden');
}

function impactClass(points) {
  const numeric = Number(points);
  if (numeric > 0) return 'negative';
  if (numeric < 0) return 'positive';
  return 'neutral';
}

function severityClass(severity) {
  const normalized = String(severity || 'INFO').toLowerCase();
  if (normalized === 'high') return 'high';
  if (normalized === 'warning') return 'warning';
  return 'info';
}

function formatImpact(points) {
  const numeric = Number(points);
  if (!Number.isFinite(numeric)) return '0 pts';
  if (numeric > 0) return `+${numeric} pts`;
  if (numeric < 0) return `${numeric} pts`;
  return '0 pts';
}

function flattenEvidence(evidence, prefix = '') {
  if (evidence === null || typeof evidence === 'undefined') {
    return [];
  }
  if (typeof evidence !== 'object') {
    return [{ key: prefix || 'value', value: evidence }];
  }
  if (Array.isArray(evidence)) {
    if (!evidence.length) {
      return [];
    }
    return [{ key: prefix || 'items', value: evidence.join(', ') }];
  }

  return Object.entries(evidence).flatMap(([key, value]) => {
    const nextPrefix = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return flattenEvidence(value, nextPrefix);
    }
    if (Array.isArray(value)) {
      return [{ key: nextPrefix, value: value.join(', ') }];
    }
    return [{ key: nextPrefix, value }];
  });
}

function renderDetails(checks) {
  const detailsList = byId('detailsList');
  detailsList.innerHTML = '';
  if (!checks.length) {
    const li = document.createElement('li');
    li.className = 'detail-empty';
    li.textContent = 'No detailed checks available.';
    detailsList.appendChild(li);
  } else {
    const sortedChecks = [...checks].sort((a, b) => Math.abs(Number(b?.risk_points) || 0) - Math.abs(Number(a?.risk_points) || 0));
    sortedChecks.forEach((check) => {
      const li = document.createElement('li');
      li.className = 'detail-item';

      const head = document.createElement('div');
      head.className = 'detail-head';

      const title = document.createElement('p');
      title.className = 'detail-title';
      title.textContent = String(check.check_name || 'Unknown check');

      const chips = document.createElement('div');
      chips.className = 'detail-chips';

      const impact = document.createElement('span');
      impact.className = `impact-chip ${impactClass(check.risk_points)}`;
      impact.textContent = formatImpact(check.risk_points);

      const severity = document.createElement('span');
      severity.className = `severity-chip ${severityClass(check.severity)}`;
      severity.textContent = String(check.severity || 'INFO').toUpperCase();

      chips.appendChild(impact);
      chips.appendChild(severity);
      head.appendChild(title);
      head.appendChild(chips);

      const explanation = document.createElement('p');
      explanation.className = 'detail-explanation';
      explanation.textContent = String(check.explanation || 'No explanation available.');

      const meta = document.createElement('p');
      meta.className = 'detail-meta';
      meta.textContent = `Confidence ${formatConfidence(check.confidence)}`;

      const evidencePairs = flattenEvidence(check.evidence || {});
      let evidenceWrap = null;
      if (evidencePairs.length) {
        evidenceWrap = document.createElement('details');
        evidenceWrap.className = 'detail-evidence';
        const evidenceSummary = document.createElement('summary');
        evidenceSummary.textContent = 'Technical evidence';
        evidenceWrap.appendChild(evidenceSummary);

        const evidenceList = document.createElement('ul');
        evidenceList.className = 'evidence-list';
        evidencePairs.forEach((entry) => {
          const evidenceItem = document.createElement('li');
          const key = document.createElement('span');
          key.className = 'evidence-key';
          key.textContent = `${entry.key}: `;
          const value = document.createElement('span');
          value.className = 'evidence-value';
          value.textContent = String(entry.value);
          evidenceItem.appendChild(key);
          evidenceItem.appendChild(value);
          evidenceList.appendChild(evidenceItem);
        });
        evidenceWrap.appendChild(evidenceList);
      }

      li.appendChild(head);
      li.appendChild(explanation);
      li.appendChild(meta);
      if (evidenceWrap) {
        li.appendChild(evidenceWrap);
      }
      detailsList.appendChild(li);
    });
  }
  detailsList.classList.remove('hidden');
}

function sendMessage(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message || 'Service worker unavailable.' });
        return;
      }
      resolve(response || { ok: false, error: 'No response from extension worker.' });
    });
  });
}

function storageSetLocal(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => resolve());
  });
}

let scanActivityTicker = null;
let scanActivityStartedAtMs = null;
let lastExtractionKickAtMs = 0;

function stopScanActivityTicker() {
  if (scanActivityTicker) {
    clearInterval(scanActivityTicker);
    scanActivityTicker = null;
  }
  scanActivityStartedAtMs = null;
}

function renderLiveScanActivity() {
  if (!Number.isFinite(scanActivityStartedAtMs)) return;
  const elapsedMs = Math.max(0, Date.now() - scanActivityStartedAtMs);
  const elapsedSeconds = Math.max(1, Math.floor(elapsedMs / 1000));
  setSiteKind('neutral', 'Scan in progress');
  setScanActivity(true, `Scanning this site... ${elapsedSeconds}s`);
  setStatus('');
}

function startScanActivityTicker(initialElapsedMs) {
  const normalizedElapsedMs = Math.max(0, Number(initialElapsedMs) || 0);
  scanActivityStartedAtMs = Date.now() - normalizedElapsedMs;
  renderLiveScanActivity();
  if (!scanActivityTicker) {
    scanActivityTicker = setInterval(renderLiveScanActivity, 1000);
  }
}

async function maybeKickExtraction() {
  const now = Date.now();
  if (now - lastExtractionKickAtMs < 2500) {
    return;
  }
  lastExtractionKickAtMs = now;
  await triggerActiveExtraction();
}

async function refreshPopupData() {
  const response = await sendMessage({ type: 'GET_RESULT_FOR_ACTIVE_TAB' });
  const auth = resolveAuth(response?.auth || null);
  const contextKey = buildResultContextKey(response);
  if (lastResultContextKey && lastResultContextKey !== contextKey) {
    collapseAdvancedDetails(true);
  }
  lastResultContextKey = contextKey;

  if (!response?.ok) {
    clearRenderedResult();
    const activeDomain = response?.domain || '-';
    byId('siteDomain').textContent = activeDomain;
    renderAuthPanel(auth, response?.page_state || null);
    renderForceCheckCard(auth, response?.page_state || null);

    if (response?.scan_in_progress) {
      const elapsedMs = Number(response?.scan_progress?.elapsed_ms || 0);
      startScanActivityTicker(elapsedMs);
      return;
    }

    stopScanActivityTicker();
    setScanActivity(false);

    if (response?.page_state?.kind === 'not_supported') {
      setSiteKind('neutral', 'Unsupported page');
      setStatus('');
      return;
    }

    if (response?.page_state?.kind === 'detecting') {
      setSiteKind('neutral', 'Checking page type');
      setScanActivity(true, 'Checking this page...');
      setStatus('');
      return;
    }

    if (response?.page_state?.kind === 'scannable') {
      setSiteKind('neutral', 'Scan in progress');
      if (response?.scan_in_progress) {
        setScanActivity(true, 'Preparing scan...');
        setStatus('');
      } else {
        setScanActivity(false);
        setStatus(response?.error || 'Waiting to start scan...', 'info');
        await maybeKickExtraction();
      }
      return;
    }

    if (response?.page_state?.kind === 'scan_error') {
      setSiteKind('warn', 'Scan issue');
      setScanActivity(false);
      setStatus(response?.error || 'Scan failed. Please retry.', 'error');
      return;
    }

    setSiteKind('neutral', 'Unsupported page');
    setScanActivity(false);
    setStatus(response?.error || 'This page type is not currently supported.', 'info');
    return;
  }

  stopScanActivityTicker();
  setScanActivity(false);
  renderAuthPanel(auth, response?.page_state || null);
  byId('forceCheckCard').classList.add('hidden');
  renderSummary(response.result, response.domain);
}

async function beginAuthFlow() {
  const connectBtn = byId('connectBtn');
  setButtonLoading(connectBtn, 'Connecting...', true);
  try {
    const response = await sendMessage({ type: 'BEGIN_AUTH_FLOW' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not start sign-in.', 'error');
    } else {
      setStatus('Sign-in page opened. Complete sign-in there.', 'info');
    }
    renderAuthPanel(resolveAuth(response?.auth || null), null);
  } finally {
    setButtonLoading(connectBtn, '', false, false);
  }
}

async function openRegisterPage() {
  const registerBtn = byId('registerBtn');
  setButtonLoading(registerBtn, 'Opening...', true);
  try {
    const response = await sendMessage({ type: 'OPEN_REGISTER_PAGE' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not open registration page.', 'error');
      return;
    }
    setStatus('Registration page opened. Create account, then connect.', 'info');
  } finally {
    setButtonLoading(registerBtn, '', false);
  }
}

async function loadDetailedBreakdown() {
  const button = byId('loadDetailsBtn');
  setButtonLoading(button, 'Loading...', true);
  try {
    const response = await sendMessage({ type: 'GET_DETAILED_RESULT_FOR_ACTIVE_TAB' });
    if (!response?.ok) {
      renderAuthPanel(response?.auth || null);
      setStatus(response?.error || 'Could not load detailed checks.', 'error');
      return;
    }
    renderDetails(Array.isArray(response.checks) ? response.checks : []);
    setStatus('Detailed checks loaded.', 'ok');
    button.dataset.defaultLabel = 'Reload Detailed Checks';
    setHideAdvancedButtonVisible(true);
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function runForceCheck() {
  const button = byId('forceCheckBtn');
  setButtonLoading(button, 'Running...', true);
  try {
    const response = await sendMessage({ type: 'FORCE_CHECK_ACTIVE_TAB' });
    renderAuthPanel(response?.auth || null);
    if (!response?.ok) {
      setStatus(response?.error || 'Could not run force check.', 'error');
      return;
    }
    byId('forceCheckCard').classList.add('hidden');
    renderSummary(response.result, response.domain);
    setStatus('Private force check complete. Results are visible only to this signed-in user.', 'ok');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function runScanNow() {
  const button = byId('scanNowBtn');
  setButtonLoading(button, 'Scanning...', true);
  setScanActivity(true, 'Running immediate scan...');
  try {
    const response = await sendMessage({ type: 'SCAN_NOW_ACTIVE_TAB' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not run scan now.', 'error');
      return;
    }
    renderSummary(response.result, response.domain);
    setScanActivity(false);
    setStatus('Fresh scan complete.', 'ok');
  } finally {
    setButtonLoading(button, '', false);
  }
}

function setupInteractions() {
  byId('connectBtn').addEventListener('click', beginAuthFlow);
  byId('registerBtn').addEventListener('click', openRegisterPage);
  byId('loadDetailsBtn').addEventListener('click', loadDetailedBreakdown);
  byId('hideAdvancedBtn').addEventListener('click', () => {
    collapseAdvancedDetails(false);
  });
  byId('forceCheckBtn').addEventListener('click', runForceCheck);
  byId('scanNowBtn').addEventListener('click', runScanNow);
  byId('openOptions').addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });
  byId('feedbackBtn').addEventListener('click', () => {
    void (async () => {
      const domain = String(byId('siteDomain')?.textContent || '').trim();
      if (domain && domain !== '-') {
        await storageSetLocal({ feedback_prefill_domain: domain });
      }
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      }
    })();
  });
  byId('verifiedBadgeBtn').addEventListener('click', () => {
    const detail = byId('verifiedBadgeDetail');
    detail.classList.toggle('hidden');
  });
}

async function triggerActiveExtraction() {
  await sendMessage({ type: 'RUN_ACTIVE_EXTRACTION' });
}

async function isActiveTabId(tabId) {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return typeof activeTab?.id === 'number' && activeTab.id === tabId;
}

function setupLiveTabRefresh() {
  chrome.tabs.onActivated.addListener(() => {
    void refreshPopupData();
  });

  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    void (async () => {
      if (changeInfo.status !== 'loading' && changeInfo.status !== 'complete') {
        return;
      }
      if (!(await isActiveTabId(tabId))) {
        return;
      }
      await refreshPopupData();
    })();
  });
}

setupInteractions();
setupLiveTabRefresh();
chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === 'AUTH_STATE_UPDATED') {
    void (async () => {
      await maybeKickExtraction();
      await refreshPopupData();
    })();
  }
});
void triggerActiveExtraction();
void refreshPopupData();
setInterval(() => {
  void refreshPopupData();
}, 3500);
