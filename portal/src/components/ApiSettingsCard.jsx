export function ApiSettingsCard({
  apiBaseUrl,
  apiToken,
  apiSavedMessage,
  onApiBaseUrlChange,
  onApiTokenChange,
  onSave
}) {
  return (
    <section className="card">
      <h2>Portal API Settings</h2>
      <div className="api-grid">
        <label>
          API Base URL
          <input
            value={apiBaseUrl}
            onChange={(event) => onApiBaseUrlChange(event.target.value)}
            placeholder="http://localhost:8000/api"
          />
        </label>
        <label>
          API Token (optional)
          <input
            type="password"
            value={apiToken}
            onChange={(event) => onApiTokenChange(event.target.value)}
            placeholder="Optional token"
          />
        </label>
      </div>
      <div className="section-row">
        <button onClick={onSave}>Save API Settings</button>
        <span className="muted">{apiSavedMessage}</span>
      </div>
    </section>
  );
}