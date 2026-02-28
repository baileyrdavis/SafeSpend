const DEFAULT_CACHE_TTL_HOURS = 24;
const AUTH_FRESH_SKEW_MS = 45 * 1000;

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

let currentUserEmail = '';
let ongoingScans = [];
let lastAppliedFeedbackPrefill = '';

function deriveAuthFromLocal(authState, authProfile, deviceAuthSession = null) {
  const now = Date.now();
  const accessFresh = Boolean(
    authState?.access_token &&
    Number(authState?.access_expires_at_ms || 0) - now > AUTH_FRESH_SKEW_MS
  );
  const refreshAvailable = Boolean(
    authState?.refresh_token &&
    Number(authState?.refresh_expires_at_ms || 0) > now
  );
  const inProgress = Boolean(
    deviceAuthSession &&
    deviceAuthSession.status === 'pending' &&
    Number(deviceAuthSession.expires_at_ms || 0) > now
  );
  return {
    authenticated: accessFresh || (!accessFresh && refreshAvailable),
    preview_mode: !(accessFresh || (!accessFresh && refreshAvailable)),
    recovering: !accessFresh && refreshAvailable,
    refresh_available: refreshAvailable,
    in_progress: inProgress,
    verifying: false,
    user_code: inProgress ? deviceAuthSession.user_code : null,
    verification_url: inProgress ? deviceAuthSession.verification_uri_complete : null,
    user_email: String(authProfile?.user_email || ''),
    auth_error: null,
    access_expires_at_ms: authState?.access_expires_at_ms || null,
  };
}

function applyFeedbackPrefill(domainValue, { force = false } = {}) {
  const domain = String(domainValue || '').trim();
  if (!domain) {
    return;
  }
  const input = byId('feedbackDomain');
  const current = String(input.value || '').trim();
  if (force || !current || current === lastAppliedFeedbackPrefill) {
    input.value = domain;
  }
  lastAppliedFeedbackPrefill = domain;
}

function formatDuration(ms) {
  const totalSeconds = Math.max(0, Math.floor(Number(ms || 0) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}h ${String(minutes).padStart(2, '0')}m ${String(seconds).padStart(2, '0')}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
  }
  return `${seconds}s`;
}

function renderOngoingScans() {
  const empty = byId('ongoingScansEmpty');
  const list = byId('ongoingScansList');
  if (!Array.isArray(ongoingScans) || !ongoingScans.length) {
    empty.classList.remove('hidden');
    list.classList.add('hidden');
    list.innerHTML = '';
    return;
  }

  empty.classList.add('hidden');
  list.classList.remove('hidden');
  list.innerHTML = ongoingScans.map((scan) => {
    const domain = String(scan?.domain || 'Unknown domain');
    const mode = String(scan?.mode || 'public');
    const tabCount = Number(scan?.tab_count || 0);
    const elapsed = formatDuration(Number(scan?.elapsed_ms || 0));
    return `
      <article class="scan-item">
        <div class="scan-head">
          <span class="scan-domain">${domain}</span>
          <span class="scan-mode">${mode === 'private' ? 'PRIVATE' : 'PUBLIC'}</span>
        </div>
        <div class="scan-meta">
          <span>Running: ${elapsed}</span>
          <span>Watching tabs: ${tabCount}</span>
        </div>
      </article>
    `;
  }).join('');
}

async function refreshOngoingScans() {
  const response = await sendMessage({ type: 'GET_ONGOING_SCANS' });
  if (!response?.ok) {
    ongoingScans = [];
    renderOngoingScans();
    return;
  }
  ongoingScans = Array.isArray(response.scans) ? response.scans : [];
  renderOngoingScans();
}

function setAuthCheckingSpinner(visible) {
  byId('authCheckingSpinner').classList.toggle('hidden', !visible);
}

function collapseDeleteConfirmation() {
  byId('deleteConfirmPanel').classList.add('hidden');
  byId('startDeleteBtn').classList.remove('hidden');
  byId('deleteConfirmEmail').value = '';
  byId('deleteConfirmAck').checked = false;
  updateDeleteButtonState();
}

function openDeleteConfirmation() {
  byId('deleteConfirmPanel').classList.remove('hidden');
  byId('startDeleteBtn').classList.add('hidden');
  updateDeleteButtonState();
}

function updateDeleteButtonState() {
  const typedEmail = byId('deleteConfirmEmail').value.trim().toLowerCase();
  const expectedEmail = String(currentUserEmail || '').trim().toLowerCase();
  const confirmedAck = byId('deleteConfirmAck').checked;
  const canDelete = Boolean(expectedEmail) && typedEmail === expectedEmail && confirmedAck;
  byId('deleteAccountBtn').disabled = !canDelete;
}

function renderAuthSummary(auth) {
  const summary = byId('authSummaryText');
  const connectBtn = byId('connectBtn');
  const registerBtn = byId('registerBtn');
  const signOutBtn = byId('signOutBtn');
  const deleteAccountBtn = byId('deleteAccountBtn');
  const dangerZone = byId('dangerZone');
  const deleteExpectedEmail = byId('deleteExpectedEmail');
  const feedbackCard = byId('feedbackCard');

  setAuthCheckingSpinner(Boolean(auth?.in_progress || auth?.verifying || auth?.recovering));

  if (!auth) {
    summary.textContent = 'Checking account status...';
    connectBtn.classList.remove('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.add('hidden');
    dangerZone.classList.add('hidden');
    deleteAccountBtn.classList.add('hidden');
    currentUserEmail = '';
    deleteExpectedEmail.textContent = 'Sign in required';
    feedbackCard.classList.add('hidden');
    collapseDeleteConfirmation();
    return;
  }

  if (auth.authenticated) {
    currentUserEmail = String(auth.user_email || '').trim();
    summary.textContent = auth.recovering
      ? 'Restoring session...'
      : (currentUserEmail
          ? `Connected as ${currentUserEmail}. Full checks are active. `
          : 'Connected. Full backend scanning and account security are active. ');
    connectBtn.classList.add('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.remove('hidden');
    dangerZone.classList.remove('hidden');
    deleteAccountBtn.classList.remove('hidden');
    deleteExpectedEmail.textContent = currentUserEmail || 'Could not resolve account email';
    feedbackCard.classList.remove('hidden');
    const feedbackEmailInput = byId('feedbackEmail');
    if (!feedbackEmailInput.value.trim() && currentUserEmail) {
      feedbackEmailInput.value = currentUserEmail;
    }
    updateDeleteButtonState();
    return;
  }

  if (auth.in_progress) {
    const copy = auth.verifying
      ? 'Verifying account connection... '
      : (auth.user_code ? `Sign-in in progress. Use code ${auth.user_code}. ` : 'Sign-in in progress. ');
    summary.textContent = copy;
    connectBtn.textContent = 'Resume Sign In';
    connectBtn.classList.remove('hidden');
    registerBtn.classList.add('hidden');
    signOutBtn.classList.add('hidden');
    dangerZone.classList.add('hidden');
    deleteAccountBtn.classList.add('hidden');
    currentUserEmail = '';
    deleteExpectedEmail.textContent = 'Sign in required';
    feedbackCard.classList.add('hidden');
    collapseDeleteConfirmation();
    return;
  }

  summary.textContent = auth.auth_error || 'Preview mode only. Create/sign in to enable full checks.';
  connectBtn.textContent = 'Connect SafeSpend';
  connectBtn.classList.remove('hidden');
  registerBtn.classList.remove('hidden');
  signOutBtn.classList.add('hidden');
  dangerZone.classList.add('hidden');
  deleteAccountBtn.classList.add('hidden');
  currentUserEmail = '';
  deleteExpectedEmail.textContent = 'Sign in required';
  feedbackCard.classList.add('hidden');
  collapseDeleteConfirmation();
}

async function refreshAuthSummary() {
  const response = await sendMessage({ type: 'GET_AUTH_STATE' });
  renderAuthSummary(response?.auth || null);
}

async function loadSettings() {
  const [syncData, localData] = await Promise.all([
    storageGet('sync', ['cache_ttl_hours']),
    storageGet('local', ['install_hash', 'auth_state', 'auth_profile', 'device_auth_session', 'feedback_prefill_domain']),
  ]);
  byId('cacheTtlHours').value = String(syncData.cache_ttl_hours || DEFAULT_CACHE_TTL_HOURS);
  byId('installHash').textContent = localData.install_hash || 'Initializing...';
  renderAuthSummary(deriveAuthFromLocal(localData.auth_state || {}, localData.auth_profile || null, localData.device_auth_session || null));
  applyFeedbackPrefill(localData.feedback_prefill_domain, { force: true });

  // Non-blocking refreshes so the page is immediately usable.
  void refreshAuthSummary();
  void refreshOngoingScans();
}

async function saveCacheSettings() {
  const button = byId('saveCacheBtn');
  setButtonLoading(button, 'Saving...', true);
  try {
    const cacheTtlHoursRaw = Number(byId('cacheTtlHours').value);
    const cacheTtlHours = Math.max(1, Math.min(72, Number.isFinite(cacheTtlHoursRaw) ? cacheTtlHoursRaw : DEFAULT_CACHE_TTL_HOURS));
    await storageSet('sync', { cache_ttl_hours: cacheTtlHours });
    byId('cacheTtlHours').value = String(cacheTtlHours);
    setStatus('Cache settings saved.', 'success');
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
    setStatus('Sign-in page opened. Finish login there.', 'success');
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
    setStatus('Registration page opened. Create account, then connect SafeSpend.', 'success');
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
    setStatus('Signed out for this browser.', 'success');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function deleteAccount() {
  updateDeleteButtonState();
  if (byId('deleteAccountBtn').disabled) {
    setStatus('Type your account email exactly and tick the confirmation checkbox.', 'error');
    return;
  }

  const button = byId('deleteAccountBtn');
  const confirmEmail = byId('deleteConfirmEmail').value.trim();
  setButtonLoading(button, 'Deleting...', true);
  setStatus('Deleting account and related data...', 'info');
  try {
    const response = await sendMessage({ type: 'DELETE_ACCOUNT', confirm_email: confirmEmail });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not delete account.', 'error');
      return;
    }
    renderAuthSummary(response.auth || null);
    setStatus('Account deleted for this user. Extension returned to preview mode.', 'success');
  } finally {
    setButtonLoading(button, '', false);
    collapseDeleteConfirmation();
  }
}

async function clearCache() {
  const button = byId('clearCacheBtn');
  setButtonLoading(button, 'Clearing...', true);
  setStatus('Clearing cached results...', 'info');
  try {
    await sendMessage({ type: 'CLEAR_EXTENSION_CACHE' });
    setStatus('Cached scan results cleared.', 'success');
  } finally {
    setButtonLoading(button, '', false);
  }
}

async function submitFeedback() {
  const button = byId('submitFeedbackBtn');
  const category = String(byId('feedbackCategory').value || '').trim();
  const domain = String(byId('feedbackDomain').value || '').trim();
  const contactEmail = String(byId('feedbackEmail').value || '').trim();
  const message = String(byId('feedbackMessage').value || '').trim();

  if (!message || message.length < 8) {
    setStatus('Please provide a bit more detail before submitting.', 'error');
    return;
  }

  setButtonLoading(button, 'Submitting...', true);
  setStatus('Submitting feedback...', 'info');
  try {
    const response = await sendMessage({
      type: 'SUBMIT_FEEDBACK',
      payload: {
        category,
        domain,
        contact_email: contactEmail,
        message,
      },
    });
    if (!response?.ok) {
      setStatus(response?.error || 'Could not submit feedback.', 'error');
      return;
    }
    byId('feedbackMessage').value = '';
    setStatus(
      response?.delivered
        ? 'Feedback submitted and emailed successfully.'
        : 'Feedback submitted successfully.',
      'success'
    );
  } finally {
    setButtonLoading(button, '', false);
  }
}

byId('saveCacheBtn').addEventListener('click', saveCacheSettings);
byId('connectBtn').addEventListener('click', connectAccount);
byId('registerBtn').addEventListener('click', openRegisterPage);
byId('signOutBtn').addEventListener('click', signOutAccount);
byId('startDeleteBtn').addEventListener('click', openDeleteConfirmation);
byId('cancelDeleteBtn').addEventListener('click', collapseDeleteConfirmation);
byId('deleteAccountBtn').addEventListener('click', deleteAccount);
byId('clearCacheBtn').addEventListener('click', clearCache);
byId('submitFeedbackBtn').addEventListener('click', submitFeedback);
byId('deleteConfirmEmail').addEventListener('input', updateDeleteButtonState);
byId('deleteConfirmAck').addEventListener('change', updateDeleteButtonState);
chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === 'AUTH_STATE_UPDATED') {
    void refreshAuthSummary();
  }
});
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') {
    return;
  }
  if (changes.feedback_prefill_domain) {
    applyFeedbackPrefill(changes.feedback_prefill_domain.newValue, { force: false });
  }
});

void loadSettings();
setInterval(() => {
  void refreshAuthSummary();
}, 3000);
setInterval(() => {
  void refreshOngoingScans();
}, 1000);
