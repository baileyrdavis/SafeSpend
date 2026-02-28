function byId(id) {
  return document.getElementById(id);
}

function trustColor(level) {
  if (level === 'HIGH') return '#22c55e';
  if (level === 'MEDIUM') return '#f59e0b';
  return '#ef4444';
}

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '-';
  return `${Math.round(numeric * 100)}%`;
}

function renderResult(result, domain) {
  const status = byId('status');
  const summary = byId('summary');
  const reasons = byId('reasons');
  const details = byId('details');

  status.className = 'status ok';
  const suffix = result?.stale_cache ? ' (stale cache)' : result?.from_cache ? ' (cached)' : '';
  status.textContent = `Latest scan loaded for ${domain}${suffix}`;

  summary.classList.remove('hidden');
  reasons.classList.remove('hidden');
  details.classList.remove('hidden');

  byId('riskScore').textContent = String(result.risk_score ?? '-');

  const trustLevel = byId('trustLevel');
  trustLevel.textContent = String(result.trust_level || '-');
  trustLevel.style.color = trustColor(result.trust_level);

  byId('scoreConfidence').textContent = formatConfidence(result.score_confidence);
  byId('lastScannedAt').textContent = formatDate(result.last_scanned_at);

  const reasonsList = byId('reasonsList');
  reasonsList.innerHTML = '';

  const topReasons = Array.isArray(result.top_reasons) ? result.top_reasons : [];
  if (topReasons.length === 0) {
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

  const detailsList = byId('detailsList');
  detailsList.innerHTML = '';
  const checks = Array.isArray(result.checks) ? result.checks : [];
  checks.forEach((check) => {
    const li = document.createElement('li');
    const sign = check.risk_points >= 0 ? '+' : '';
    li.textContent = `${check.check_name} | ${sign}${check.risk_points} | ${check.severity} | ${check.explanation}`;
    detailsList.appendChild(li);
  });
}

function renderError(message) {
  const status = byId('status');
  status.className = 'status error';
  status.textContent = message;
}

function setupInteractions() {
  const toggleBtn = byId('toggleDetails');
  const detailsList = byId('detailsList');
  const optionsBtn = byId('openOptions');

  toggleBtn.addEventListener('click', () => {
    const isHidden = detailsList.classList.toggle('hidden');
    toggleBtn.textContent = isHidden ? 'Show Detailed Breakdown' : 'Hide Detailed Breakdown';
  });

  optionsBtn.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });
}

setupInteractions();

chrome.runtime.sendMessage({ type: 'GET_RESULT_FOR_ACTIVE_TAB' }, (response) => {
  if (chrome.runtime.lastError) {
    renderError('Unable to connect to extension worker. Reload extension.');
    return;
  }

  if (!response?.ok) {
    renderError(response?.error || 'No scan data for this tab yet.');
    return;
  }

  renderResult(response.result, response.domain);
});