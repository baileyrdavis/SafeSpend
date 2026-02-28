import { formatDate, trustClass } from '../lib/formatters';

export function SitesCard({
  sites,
  sitesError,
  sitesLoading,
  trustFilter,
  minRiskFilter,
  queryFilter,
  onTrustFilterChange,
  onMinRiskFilterChange,
  onQueryFilterChange,
  onRefresh
}) {
  return (
    <section className="card">
      <div className="section-row">
        <h2>Indexed Sites</h2>
        <button onClick={onRefresh} disabled={sitesLoading}>
          {sitesLoading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      <div className="filters">
        <label>
          Trust
          <select value={trustFilter} onChange={(event) => onTrustFilterChange(event.target.value)}>
            <option value="">All</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </label>
        <label>
          Min Score
          <input
            type="number"
            min="0"
            max="100"
            value={minRiskFilter}
            onChange={(event) => onMinRiskFilterChange(Number(event.target.value || 0))}
          />
        </label>
        <label>
          Domain Contains
          <input value={queryFilter} onChange={(event) => onQueryFilterChange(event.target.value)} placeholder="example" />
        </label>
        <button onClick={onRefresh} disabled={sitesLoading}>Apply Filters</button>
      </div>

      {sitesError ? <p className="error">{sitesError}</p> : null}

      {sites.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Score</th>
                <th>Trust</th>
                <th>Country</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => (
                <tr key={site.domain}>
                  <td>{site.domain}</td>
                  <td>{site.overall_risk_score}</td>
                  <td><span className={trustClass(site.trust_level)}>{site.trust_level}</span></td>
                  <td>{site.primary_country_guess || '-'}</td>
                  <td>{formatDate(site.last_scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">No sites loaded for the current filter.</p>
      )}
    </section>
  );
}