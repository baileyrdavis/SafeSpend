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

function sendMessage(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message || 'Extension worker unavailable.' });
        return;
      }
      resolve(response || { ok: false, error: 'No response from extension worker.' });
    });
  });
}

function setStatus(message, type = 'success') {
  const status = byId('status');
  status.className = `status ${type}`;
  status.textContent = message;
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

function renderAuthSummary(auth) {
  const summary = byId('authSummary');
  const connectBtn = byId('connectBtn');
  const registerBtn = byId('registerBtn');
  const signOutBtn = byId('signOutBtn');
  const deleteAccountBtn = byId('deleteAccountBtn');

  if (!auth) {
    summary.textContent = 'Checking account status...';
    connectBtn.classList.remove('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.add('hidden');
    deleteAccountBtn.classList.add('hidden');
    return;
  }

  if (auth.authenticated) {
    summary.textContent = 'Connected. Full backend scanning and account security are active.';
    connectBtn.classList.add('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.remove('hidden');
    deleteAccountBtn.classList.remove('hidden');
    return;
  }

  if (auth.in_progress) {
    summary.textContent = auth.user_code
      ? `Sign-in in progress. Use code ${auth.user_code}.`
      : 'Sign-in in progress.';
    connectBtn.textContent = 'Resume Sign In';
    connectBtn.classList.remove('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.add('hidden');
    deleteAccountBtn.classList.add('hidden');
    return;
  }

  summary.textContent = auth.auth_error || 'Preview mode only. Create/sign in to enable full checks.';
  connectBtn.textContent = 'Connect SafeSpend';
  connectBtn.classList.remove('hidden');
  registerBtn.classList.remove('hidden');
  signOutBtn.classList.add('hidden');
  deleteAccountBtn.classList.add('hidden');
}

async function refreshAuthSummary() {
  const response = await sendMessage({ type: 'GET_AUTH_STATE' });
  renderAuthSummary(response?.auth || null);
}

async function loadSettings() {
  const syncData = await storageGet('sync', ['api_base_url', 'cache_ttl_hours']);
  const configResponse = await sendMessage({ type: 'GET_EXTENSION_CONFIG' });

  byId('apiBaseUrl').value = syncData.api_base_url || DEFAULT_API_BASE_URL;
  byId('cacheTtlHours').value = String(syncData.cache_ttl_hours || DEFAULT_CACHE_TTL_HOURS);
  byId('installHash').textContent = configResponse?.install_hash || 'Not initialized yet.';

  renderAuthSummary(configResponse?.auth || null);
}

async function saveSettings() {
  const button = byId('saveBtn');
  setButtonLoading(button, 'Saving...', true);
  try {
    const currentSettings = await storageGet('sync', ['api_base_url']);
    const apiBaseUrl = byId('apiBaseUrl').value.trim().replace(/\/$/, '');
    const cacheTtlHoursRaw = Number(byId('cacheTtlHours').value);
    const cacheTtlHours = Math.max(1, Math.min(72, Number.isFinite(cacheTtlHoursRaw) ? cacheTtlHoursRaw : DEFAULT_CACHE_TTL_HOURS));

    if (!apiBaseUrl) {
      setStatus('API base URL is required.', 'error');
      return;
    }

    const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(apiBaseUrl);
    if (!apiBaseUrl.startsWith('https://') && !isLocalhost) {
      setStatus('Use HTTPS for non-localhost API URLs.', 'error');
      return;
    }

    await storageSet('sync', {
      api_base_url: apiBaseUrl,
      cache_ttl_hours: cacheTtlHours
    });

    if ((currentSettings.api_base_url || DEFAULT_API_BASE_URL).replace(/\/$/, '') !== apiBaseUrl) {
      await sendMessage({ type: 'SIGN_OUT' });
      await sendMessage({ type: 'CLEAR_EXTENSION_CACHE' });
      renderAuthSummary({ authenticated: false, in_progress: false, auth_error: '' });
      setStatus('Settings saved. Please reconnect SafeSpend for this API.', 'success');
      return;
    }

    setStatus('Settings saved.');
  } finally {
    setButtonLoading(button, '', false, false);
  }
}

async function testConnection() {
  const button = byId('testBtn');
  setButtonLoading(button, 'Testing...', true);
  const apiBaseUrl = byId('apiBaseUrl').value.trim().replace(/\/$/, '');
  if (!apiBaseUrl) {
    setStatus('Enter API base URL before testing.', 'error');
    setButtonLoading(button, '', false);
    return;
  }

  try {
    const response = await fetch(`${apiBaseUrl}/api/health`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    setStatus('Connection OK.');
  } catch (error) {
    setStatus(`Connection failed: ${error.message || 'unknown error'}`, 'error');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function connectAccount() {
  const button = byId('connectBtn');
  setButtonLoading(button, 'Connecting...', true);
  setStatus('Starting sign-in flow...', 'info');
  try {
    const response = await sendMessage({ type: 'BEGIN_AUTH_FLOW' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not start sign-in.', 'error');
      renderAuthSummary(response?.auth || null);
      return;
    }

    renderAuthSummary(response.auth || null);
    setStatus('Sign-in page opened. Finish login there, then return here.');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function openRegisterPage() {
  const button = byId('registerBtn');
  setButtonLoading(button, 'Opening...', true);
  try {
    const response = await sendMessage({ type: 'OPEN_REGISTER_PAGE' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not open registration page.', 'error');
      return;
    }
    setStatus('Registration page opened. Create account, then connect SafeSpend.');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function signOutAccount() {
  const button = byId('signOutBtn');
  setButtonLoading(button, 'Signing out...', true);
  setStatus('Signing out...', 'info');
  try {
    const response = await sendMessage({ type: 'SIGN_OUT' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not sign out.', 'error');
      return;
    }
    renderAuthSummary(response.auth || null);
    setStatus('Signed out for this browser.');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function deleteAccount() {
  const confirmed = window.confirm(
    'Delete your SafeSpend account and install-linked data? This cannot be undone.',
  );
  if (!confirmed) {
    return;
  }

  const button = byId('deleteAccountBtn');
  setButtonLoading(button, 'Deleting...', true);
  setStatus('Deleting account and related data...', 'info');
  try {
    const response = await sendMessage({ type: 'DELETE_ACCOUNT' });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not delete account.', 'error');
      return;
    }
    renderAuthSummary(response.auth || null);
    setStatus('Account deleted for this user. Extension returned to preview mode.');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function clearCache() {
  const button = byId('clearCacheBtn');
  setButtonLoading(button, 'Clearing...', true);
  setStatus('Clearing cached results...', 'info');
  try {
    await sendMessage({ type: 'CLEAR_EXTENSION_CACHE' });
    setStatus('Cached scan results cleared.');
  } finally {
    setButtonLoading(button, '', false);
  }
}

byId('saveBtn').addEventListener('click', saveSettings);
byId('testBtn').addEventListener('click', testConnection);
byId('connectBtn').addEventListener('click', connectAccount);
byId('registerBtn').addEventListener('click', openRegisterPage);
byId('signOutBtn').addEventListener('click', signOutAccount);
byId('deleteAccountBtn').addEventListener('click', deleteAccount);
byId('clearCacheBtn').addEventListener('click', clearCache);

void loadSettings();
setInterval(() => {
  void refreshAuthSummary();
}, 3000);
