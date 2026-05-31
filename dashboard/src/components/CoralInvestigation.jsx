import { useState, useEffect } from 'react';
import {
  Search, Database, Shield, Activity, AlertTriangle, CheckCircle,
  ChevronDown, ChevronRight, Clock, ExternalLink
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const riskColor = (score) => {
  if (score >= 75) return 'var(--color-danger)';
  if (score >= 50) return 'var(--color-warning)';
  if (score >= 20) return 'var(--color-accent)';
  return 'var(--color-success)';
};

export default function CoralInvestigation({ compact = false }) {
  const [investigations, setInvestigations] = useState([]);
  const [coralStatus, setCoralStatus] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sqlInput, setSqlInput] = useState('');
  const [sqlResults, setSqlResults] = useState(null);
  const [sqlError, setSqlError] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const [invResp, statusResp] = await Promise.all([
          fetch(`${API_BASE}/api/coral/investigations?limit=20`),
          fetch(`${API_BASE}/api/coral/status`),
        ]);
        if (invResp.ok) setInvestigations(await invResp.json());
        if (statusResp.ok) setCoralStatus(await statusResp.json());
      } catch (_) { /* backend not running */ }
      setLoading(false);
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const runSql = async () => {
    if (!sqlInput.trim()) return;
    setSqlError('');
    setSqlResults(null);
    try {
      const resp = await fetch(`${API_BASE}/api/coral/sql?query=${encodeURIComponent(sqlInput.trim())}`, { method: 'POST' });
      if (resp.ok) setSqlResults(await resp.json());
      else setSqlError(`Error: ${resp.status} ${resp.statusText}`);
    } catch (e) {
      setSqlError(`Connection error: ${e.message}`);
    }
  };

  const triggerInvestigation = async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/coral/investigations/trigger`, { method: 'POST' });
      if (resp.ok) {
        const report = await resp.json();
        setInvestigations((prev) => [report, ...prev].slice(0, 200));
      }
    } catch (_) {}
  };

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Search size={14} /> Coral Investigations</span>
        </div>
        <div className="empty-state">
          <div className="spinner" />
          <span className="text-muted text-sm">Connecting to Coral engine…</span>
        </div>
      </div>
    );
  }

  const engine = coralStatus?.coral_engine ?? {};
  const investigator = coralStatus?.investigator ?? {};

  return (
    <div className="card" style={compact ? {} : { gridColumn: '1 / -1' }}>
      <div className="card-header">
        <span className="card-title"><Search size={14} /> Coral Investigation Engine</span>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className={`tag ${engine.available ? '' : 'tag-danger'}`}>
            {engine.available ? 'Coral Online' : 'No Coral Binary'}
          </span>
          <span className="tag">{engine.source_count ?? 0} sources</span>
          <span className="tag">{investigator.investigation_count ?? 0} investigations</span>
          <button className="btn btn-sm" onClick={triggerInvestigation} type="button">
            Run Investigation
          </button>
        </div>
      </div>

      {!compact && (
        <>
          {/* SQL Console */}
          <div className="card-section" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '12px' }}>
            <div className="text-sm" style={{ marginBottom: '8px', fontWeight: 600 }}>
              <Database size={12} /> Coral SQL Console
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={sqlInput}
                onChange={(e) => setSqlInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runSql()}
                placeholder="SELECT * FROM coral.tables LIMIT 10"
                className="input"
                style={{ flex: 1, fontFamily: 'monospace', fontSize: '13px' }}
              />
              <button className="btn btn-sm" onClick={runSql} type="button">
                Run
              </button>
            </div>
            {sqlError && (
              <div className="text-xs" style={{ color: 'var(--color-danger)', marginTop: '4px' }}>{sqlError}</div>
            )}
            {sqlResults && (
              <pre className="code-block" style={{ marginTop: '8px', maxHeight: '200px', overflow: 'auto' }}>
                {JSON.stringify(sqlResults.slice(0, 10), null, 2)}
                {sqlResults.length > 10 && `\n… and ${sqlResults.length - 10} more rows`}
              </pre>
            )}
          </div>
        </>
      )}

      {/* Investigation List */}
      {investigations.length === 0 ? (
        <div className="empty-state">
          <CheckCircle size={40} style={{ opacity: 0.3, color: 'var(--color-success)' }} />
          <p>No investigations yet.</p>
          <div className="text-xs text-muted">
            Install Coral sources and trigger an investigation to see results here.
          </div>
        </div>
      ) : (
        <ul className="threat-feed">
          {(compact ? investigations.slice(0, 5) : investigations).map((inv) => {
            const expanded = expandedId === inv.investigation_id;
            const resultCount = Object.keys(inv.coral_results ?? {}).length;
            const errorCount = (inv.errors ?? []).length;

            return (
              <li key={inv.investigation_id} className="threat-item" style={{ cursor: 'pointer' }}>
                <div
                  onClick={() => setExpandedId(expanded ? null : inv.investigation_id)}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', width: '100%' }}
                >
                  <span className={`threat-badge ${inv.decision}`}>
                    {inv.decision}
                  </span>
                  <div className="threat-info" style={{ flex: 1 }}>
                    <div className="threat-topic truncate">
                      Investigation #{inv.investigation_id?.slice(0, 8)}
                    </div>
                    <div className="threat-meta">
                      {resultCount} queries · {errorCount} errors ·
                      {inv.timestamp ? new Date(inv.timestamp).toLocaleTimeString() : '—'}
                    </div>
                  </div>
                  <span className="threat-risk glow-text" style={{ color: riskColor(inv.risk_score) }}>
                    {inv.risk_score}
                  </span>
                  {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </div>

                {expanded && (
                  <div style={{ marginTop: '8px', paddingLeft: '8px', borderLeft: '2px solid var(--border-color)' }}>
                    {Object.entries(inv.coral_results ?? {}).map(([queryName, rows]) => (
                      <div key={queryName} style={{ marginBottom: '8px' }}>
                        <div className="text-xs" style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--color-accent)' }}>
                          <Database size={10} /> {queryName}
                        </div>
                        <pre className="code-block" style={{ maxHeight: '120px', overflow: 'auto', fontSize: '11px' }}>
                          {JSON.stringify(Array.isArray(rows) ? rows.slice(0, 3) : rows, null, 2)}
                          {Array.isArray(rows) && rows.length > 3 && `\n… and ${rows.length - 3} more rows`}
                        </pre>
                      </div>
                    ))}
                    {errorCount > 0 && (
                      <div className="text-xs" style={{ color: 'var(--color-warning)' }}>
                        <AlertTriangle size={10} /> {errorCount} query error(s): {inv.errors?.join(', ')}
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {!compact && (
        <div style={{ marginTop: '12px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div className="stat-card" style={{ flex: '1', minWidth: '120px', padding: '8px' }}>
            <div className="stat-label text-xs">SQL Queries</div>
            <div className="stat-value" style={{ fontSize: '18px' }}>{engine.sql_queries ?? 0}</div>
          </div>
          <div className="stat-card" style={{ flex: '1', minWidth: '120px', padding: '8px' }}>
            <div className="stat-label text-xs">Sources</div>
            <div className="stat-value" style={{ fontSize: '18px' }}>{engine.source_count ?? 0}</div>
          </div>
          <div className="stat-card" style={{ flex: '1', minWidth: '120px', padding: '8px' }}>
            <div className="stat-label text-xs">Investigations</div>
            <div className="stat-value" style={{ fontSize: '18px' }}>{investigator.investigation_count ?? 0}</div>
          </div>
          <div className="stat-card" style={{ flex: '1', minWidth: '120px', padding: '8px' }}>
            <div className="stat-label text-xs">Errors</div>
            <div className="stat-value" style={{ fontSize: '18px', color: 'var(--color-danger)' }}>{engine.errors ?? 0}</div>
          </div>
        </div>
      )}
    </div>
  );
}
