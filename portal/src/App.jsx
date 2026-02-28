import { useEffect, useState } from 'react';

import { ApiSettingsCard } from './components/ApiSettingsCard';
import { DomainToolsCard } from './components/DomainToolsCard';
import { SitesCard } from './components/SitesCard';
import { createApiClient } from './lib/apiClient';
import { initialFromStorage, normalizeDomain } from './lib/formatters';

const DEFAULT_API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api').replace(/\/$/, '');
const DEFAULT_API_TOKEN = import.meta.env.VITE_API_TOKEN || '';

export default function App() {
  const [apiBaseUrl, setApiBaseUrl] = useState(() => initialFromStorage('portal_api_base_url', DEFAULT_API_BASE_URL));
  const [apiToken, setApiToken] = useState(() => initialFromStorage('portal_api_token', DEFAULT_API_TOKEN));
  const [apiSavedMessage, setApiSavedMessage] = useState('');

  const [domain, setDomain] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [lookupError, setLookupError] = useState('');
  const [lookupLoading, setLookupLoading] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  const [sites, setSites] = useState([]);
  const [sitesError, setSitesError] = useState('');
  const [sitesLoading, setSitesLoading] = useState(false);

  const [trustFilter, setTrustFilter] = useState('');
  const [minRiskFilter, setMinRiskFilter] = useState(0);
  const [queryFilter, setQueryFilter] = useState('');

  const apiClient = createApiClient(apiBaseUrl, apiToken);

  useEffect(() => {
    loadSites();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function saveApiSettings() {
    const cleanBase = apiClient.activeBaseUrl;
    if (!cleanBase) {
      setApiSavedMessage('API base URL is required.');
      return;
    }

    window.localStorage.setItem('portal_api_base_url', cleanBase);
    window.localStorage.setItem('portal_api_token', apiToken.trim());
    setApiSavedMessage('API settings saved.');
  }

  async function lookupDomain(normalizedDomain) {
    const payload = await apiClient.fetchJson(`/site/${encodeURIComponent(normalizedDomain)}`);
    setLookupResult(payload);
    setScanResult(null);
  }

  async function runLookup(event) {
    event.preventDefault();
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      setLookupError('Enter a domain first.');
      setLookupResult(null);
      return;
    }

    setLookupLoading(true);
    setLookupError('');

    try {
      await lookupDomain(normalized);
    } catch (error) {
      setLookupResult(null);
      setLookupError(error.message || 'Lookup failed.');
    } finally {
      setLookupLoading(false);
    }
  }

  async function runManualScan() {
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      setLookupError('Enter a domain first.');
      return;
    }

    setScanLoading(true);
    setLookupError('');

    try {
      const payload = await apiClient.fetchJson('/scan', {
        method: 'POST',
        body: JSON.stringify({
          domain: normalized,
          extension_version: 'portal-manual',
          triggered_by: 'MANUAL_LOOKUP',
          extracted_signals: {
            is_ecommerce: true,
            source: 'portal_manual'
          }
        })
      });

      setScanResult(payload);
      await lookupDomain(normalized);
      await loadSites();
    } catch (error) {
      setScanResult(null);
      setLookupError(error.message || 'Scan failed.');
    } finally {
      setScanLoading(false);
    }
  }

  async function forceRescanIndexedDomain() {
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      setLookupError('Enter a domain first.');
      return;
    }

    setScanLoading(true);
    setLookupError('');

    try {
      const payload = await apiClient.fetchJson(`/site/${encodeURIComponent(normalized)}/rescan`, {
        method: 'POST',
        body: JSON.stringify({
          extension_version: 'portal-rescan',
          extracted_signals: { is_ecommerce: true, source: 'portal_rescan' }
        })
      });

      setScanResult(payload);
      await lookupDomain(normalized);
      await loadSites();
    } catch (error) {
      setLookupError(error.message || 'Rescan failed.');
    } finally {
      setScanLoading(false);
    }
  }

  async function loadSites() {
    setSitesLoading(true);
    setSitesError('');

    try {
      const search = new URLSearchParams();
      search.set('limit', '100');
      if (trustFilter) search.set('trust_level', trustFilter);
      if (Number(minRiskFilter) > 0) search.set('min_risk_score', String(minRiskFilter));
      if (queryFilter.trim()) search.set('q', queryFilter.trim());

      const payload = await apiClient.fetchJson(`/sites?${search.toString()}`);
      setSites(payload.results || []);
    } catch (error) {
      setSitesError(error.message || 'Failed to load sites.');
    } finally {
      setSitesLoading(false);
    }
  }

  return (
    <div className="page">
      <header className="hero">
        <h1>SafeSpend Portal</h1>
        <p>Domain lookup, manual scan control, and indexed risk monitoring.</p>
      </header>

      <ApiSettingsCard
        apiBaseUrl={apiBaseUrl}
        apiToken={apiToken}
        apiSavedMessage={apiSavedMessage}
        onApiBaseUrlChange={setApiBaseUrl}
        onApiTokenChange={setApiToken}
        onSave={saveApiSettings}
      />

      <DomainToolsCard
        domain={domain}
        lookupResult={lookupResult}
        scanResult={scanResult}
        lookupError={lookupError}
        lookupLoading={lookupLoading}
        scanLoading={scanLoading}
        onDomainChange={setDomain}
        onLookup={runLookup}
        onManualScan={runManualScan}
        onForceRescan={forceRescanIndexedDomain}
      />

      <SitesCard
        sites={sites}
        sitesError={sitesError}
        sitesLoading={sitesLoading}
        trustFilter={trustFilter}
        minRiskFilter={minRiskFilter}
        queryFilter={queryFilter}
        onTrustFilterChange={setTrustFilter}
        onMinRiskFilterChange={setMinRiskFilter}
        onQueryFilterChange={setQueryFilter}
        onRefresh={loadSites}
      />
    </div>
  );
}
