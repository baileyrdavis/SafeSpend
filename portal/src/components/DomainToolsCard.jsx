import { formatConfidence, formatDate, trustClass } from '../lib/formatters';

export function DomainToolsCard({
  domain,
  lookupResult,
  scanResult,
  lookupError,
  lookupLoading,
  scanLoading,
  onDomainChange,
  onLookup,
  onManualScan,
  onForceRescan
}) {
  return (
    <section className="card">
      <h2>Lookup or Scan Domain</h2>
      <form onSubmit={onLookup} className="lookup-form">
        <input
          value={domain}
          onChange={(event) => onDomainChange(event.target.value)}
          placeholder="example.com"
          aria-label="Domain"
        />
        <button type="submit" disabled={lookupLoading}>
          {lookupLoading ? 'Looking up...' : 'Lookup'}
        </button>
      </form>

      <div className="actions-inline">
        <button onClick={onManualScan} disabled={scanLoading}>
          {scanLoading ? 'Scanning...' : 'Run Manual Scan'}
        </button>
        <button onClick={onForceRescan} disabled={scanLoading}>
          {scanLoading ? 'Rescanning...' : 'Force Rescan Indexed Domain'}
        </button>
      </div>

      {lookupError ? <p className="error">{lookupError}</p> : null}

      {scanResult ? (
        <div className="lookup-result">
          <h3>Latest Scan Response</h3>
          <div className="result-row">
            <span>Risk Score</span>
            <strong>{scanResult.risk_score}</strong>
          </div>
          <div className="result-row">
            <span>Trust Level</span>
            <span className={trustClass(scanResult.trust_level)}>{scanResult.trust_level}</span>
          </div>
          <div className="result-row">
            <span>Confidence</span>
            <strong>{formatConfidence(scanResult.score_confidence)}</strong>
          </div>
          <div className="result-row">
            <span>Last Scanned</span>
            <strong>{formatDate(scanResult.last_scanned_at)}</strong>
          </div>
        </div>
      ) : null}

      {lookupResult ? (
        <div className="lookup-result">
          <h3>Indexed Site Details</h3>
          <div className="result-row">
            <span>Domain</span>
            <strong>{lookupResult.domain}</strong>
          </div>
          <div className="result-row">
            <span>Risk Score</span>
            <strong>{lookupResult.overall_risk_score}</strong>
          </div>
          <div className="result-row">
            <span>Trust Level</span>
            <span className={trustClass(lookupResult.trust_level)}>{lookupResult.trust_level}</span>
          </div>
          <div className="result-row">
            <span>Country Guess</span>
            <strong>{lookupResult.primary_country_guess || '-'}</strong>
          </div>
          <div className="result-row">
            <span>Last Scanned</span>
            <strong>{formatDate(lookupResult.last_scanned_at)}</strong>
          </div>

          {lookupResult.latest_scan?.check_results?.length ? (
            <div className="checks">
              <h3>Check Breakdown</h3>
              <ul>
                {lookupResult.latest_scan.check_results.map((check) => (
                  <li key={`${check.check_name}-${check.explanation}`}>
                    <span>{check.check_name}</span>
                    <strong>{check.risk_points >= 0 ? `+${check.risk_points}` : check.risk_points}</strong>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}