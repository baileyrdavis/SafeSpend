function byId(id) {
  return document.getElementById(id);
}

function trustColor(level) {
  if (level === 'HIGH') return '#22c55e';
  if (level === 'MEDIUM') return '#f59e0b';
  return '#ef4444';
}

const LOCAL_DATE_TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
  hour12: true
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

function setStatus(message, type = 'info') {
  const status = byId('status');
  status.className = `status ${type}`;
  status.textContent = message;
}

function setScanActivity(visible, message = 'Scanning this site now...') {
  const panel = byId('scanActivity');
  const label = byId('scanActivityLabel');
  if (!panel || !label) return;
  label.textContent = message;
  panel.classList.toggle('hidden', !visible);
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

function renderAuthState(auth) {
  const panel = byId('authState');
  const connectBtn = byId('connectBtn');
  const registerBtn = byId('registerBtn');

  if (!auth) {
    panel.className = 'auth-card info';
    panel.textContent = 'Checking sign-in status...';
    connectBtn.classList.add('hidden');
    registerBtn.classList.add('hidden');
    return;
  }

  if (auth.authenticated) {
    panel.className = 'auth-card ok';
    panel.textContent = 'Connected: full SafeSpend checks, brand spoof detection, and account-backed session security are active.';
    connectBtn.classList.add('hidden');
    registerBtn.classList.add('hidden');
    return;
  }

  if (auth.in_progress) {
    panel.className = 'auth-card info';
    panel.textContent = auth.user_code
      ? `Finish sign-in with code ${auth.user_code}.`
      : 'Finish sign-in to activate scans.';
    connectBtn.textContent = 'Resume Sign In';
    connectBtn.classList.remove('hidden');
    registerBtn.classList.add('hidden');
    return;
  }

  panel.className = 'auth-card info';
  panel.textContent = auth.auth_error
    ? `${auth.auth_error} Preview mode active with basic checks.`
    : 'Preview mode active: sign in for full backend verification and account protections.';
  connectBtn.textContent = 'Connect SafeSpend';
  connectBtn.classList.remove('hidden');
  registerBtn.classList.remove('hidden');
}

function renderSummary(result, domain) {
  const suffix = result?.stale_cache ? ' (stale cache)' : result?.from_cache ? ' (cached)' : '';
  setScanActivity(false);
  if (result?.preview_mode) {
    setStatus(`Preview scan loaded for ${domain}${suffix}`, 'info');
  } else {
    setStatus(`Latest scan loaded for ${domain}${suffix}`, 'ok');
  }

  byId('summary').classList.remove('hidden');
  byId('reasons').classList.remove('hidden');
  if (result?.preview_mode) {
    byId('details').classList.add('hidden');
  } else {
    byId('details').classList.remove('hidden');
  }

  byId('riskScore').textContent = String(result.risk_score ?? '-');

  const trustLevel = byId('trustLevel');
  trustLevel.textContent = String(result.trust_level || '-');
  trustLevel.style.color = trustColor(result.trust_level);

  byId('scoreConfidence').textContent = formatConfidence(result.score_confidence);
  byId('lastScannedAt').textContent = formatDate(result.last_scanned_at);
  byId('disclaimerText').textContent = result.disclaimer || 'Risk score is informational only.';

  const reasonsList = byId('reasonsList');
  reasonsList.innerHTML = '';
  const topReasons = Array.isArray(result.top_reasons) ? result.top_reasons : [];
  if (!topReasons.length) {
    const li = document.createElement('li');
    li.textContent = 'No high-risk triggers in top reasons.';
    reasonsList.appendChild(li);
  } else {
    topReasons.forEach((reason) => {
      const li = document.createElement('li');
      li.textContent = `${reason.check_name}: +${reason.risk_points} (${reason.explanation})`;
      reasonsList.appendChild(li);
    });
  }
}

function renderDetails(checks) {
  const detailsList = byId('detailsList');
  detailsList.innerHTML = '';

  if (!checks.length) {
    const li = document.createElement('li');
    li.textContent = 'No detailed checks available for this scan.';
    detailsList.appendChild(li);
  } else {
    checks.forEach((check) => {
      const li = document.createElement('li');
      const sign = Number(check.risk_points) >= 0 ? '+' : '';
      li.textContent = `${check.check_name} | ${sign}${check.risk_points} | ${check.severity} | ${check.explanation}`;
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

async function refreshPopupData() {
  const response = await sendMessage({ type: 'GET_RESULT_FOR_ACTIVE_TAB' });
  renderAuthState(response?.auth || null);

  if (!response?.ok) {
    if (response?.scan_in_progress) {
      const elapsedMs = Number(response?.scan_progress?.elapsed_ms || 0);
      const elapsedSeconds = Math.max(1, Math.round(elapsedMs / 1000));
      setScanActivity(true, `Scanning this site... ${elapsedSeconds}s`);
      setStatus(`Running scan for this site... (${elapsedSeconds}s)`, 'info');
      return;
    }
    setScanActivity(false);
    if (response?.auth_required) {
      setStatus('Sign in required before scans can run.', 'error');
      return;
    }
    setStatus(response?.error || 'No scan data for this tab yet.', 'info');
    return;
  }

  renderSummary(response.result, response.domain);
}

async function triggerActiveExtraction() {
  await sendMessage({ type: 'RUN_ACTIVE_EXTRACTION' });
}

async function isActiveTabId(tabId) {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return typeof activeTab?.id === 'number' && activeTab.id === tabId;
}

async function beginAuthFlow() {
  const connectBtn = byId('connectBtn');
  setButtonLoading(connectBtn, 'Connecting...', true);
  setStatus('Starting sign-in flow...', 'info');
  try {
    const response = await sendMessage({ type: 'BEGIN_AUTH_FLOW' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not start sign-in.', 'error');
    } else {
      setStatus('Sign-in page opened. Complete login to continue.', 'info');
    }
    renderAuthState(response?.auth || null);
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
      setStatus(response?.error || 'Could not open account registration.', 'error');
      return;
    }
    setStatus('Registration page opened. Create account, then return to connect.', 'info');
  } finally {
    setButtonLoading(registerBtn, '', false);
  }
}

async function loadDetailedBreakdown() {
  const button = byId('loadDetailsBtn');
  setButtonLoading(button, 'Loading Details...', true);
  setStatus('Loading detailed checks...', 'info');
  try {
    const response = await sendMessage({ type: 'GET_DETAILED_RESULT_FOR_ACTIVE_TAB' });
    if (!response?.ok) {
      renderAuthState(response?.auth || null);
      setStatus(response?.error || 'Could not load detailed checks.', 'error');
      return;
    }

    renderDetails(Array.isArray(response.checks) ? response.checks : []);
    setStatus('Detailed checks loaded.', 'ok');
    button.dataset.defaultLabel = 'Reload Detailed Breakdown';
  } finally {
    setButtonLoading(button, '', false);
  }
}

function setupInteractions() {
  byId('connectBtn').addEventListener('click', beginAuthFlow);
  byId('registerBtn').addEventListener('click', openRegisterPage);
  byId('loadDetailsBtn').addEventListener('click', loadDetailedBreakdown);
  byId('openOptions').addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });
}

function setupLiveTabRefresh() {
  chrome.tabs.onActivated.addListener(() => {
    void triggerActiveExtraction();
    void refreshPopupData();
  });

  chrome.tabs.onUpdated.addListener((_tabId, changeInfo, _tab) => {
    void (async () => {
      if (changeInfo.status !== 'loading' && changeInfo.status !== 'complete') {
        return;
      }
      if (!(await isActiveTabId(_tabId))) {
        return;
      }
      await triggerActiveExtraction();
      await refreshPopupData();
    })();
  });
}

setupInteractions();
setupLiveTabRefresh();
void triggerActiveExtraction();
void refreshPopupData();
setInterval(() => {
  void refreshPopupData();
}, 3500);
