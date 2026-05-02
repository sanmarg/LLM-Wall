/**
 * @fileoverview SentinelMesh — IOC store browser and node status.
 */

import { useState, useEffect } from 'react';
import { Radio } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
const SEVERITY_COLORS = [
  '', '#34d399', '#34d399', '#a3e635',
  '#facc15', '#fb923c', '#f97316',
  '#ef4444', '#dc2626', '#b91c1c', '#f43f5e'
];

/**
 * SentinelMesh component.
 * @returns {JSX.Element}
 */
export default function SentinelMesh() {
  const [status, setStatus] = useState(null);
  const [iocs, setIocs] = useState([]);
  const [matchText, setMatchText] = useState('');
  const [matchResult, setMatchResult] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [sResp, iResp] = await Promise.all([
          fetch(`${API_BASE}/api/sentinel/status`),
          fetch(`${API_BASE}/api/sentinel/iocs`),
        ]);
        if (sResp.ok) setStatus(await sResp.json());
        if (iResp.ok) setIocs(await iResp.json());
      } catch (_) { /* offline */ }
    };
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  const runMatch = async () => {
    if (!matchText.trim()) return;
    const resp = await fetch(`${API_BASE}/api/sentinel/iocs/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: matchText }),
    });
    if (resp.ok) setMatchResult(await resp.json());
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="page-header">
        <h1 className="page-title">Sentinel Mesh</h1>
        <p className="page-subtitle">Decentralised threat intelligence network</p>
      </div>

      {/* Node status */}
      {status && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">📡 Node Status</span>
            <span className="tag" style={{ color: status.running ? 'var(--color-success)' : 'var(--color-danger)' }}>
              {status.running ? '● Active' : '○ Stopped'}
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
            {[
              { k: 'Node ID',      v: status.node_id?.slice(0, 12) + '…' },
              { k: 'Total IOCs',   v: status.ioc_stats?.total_iocs ?? 0 },
              { k: 'Evicted',      v: status.ioc_stats?.eviction_count ?? 0 },
              { k: 'Peer Count',   v: status.peer_count ?? 0 },
              { k: 'Threats Seen', v: status.threat_count ?? 0 },
            ].map(({ k, v }) => (
              <div key={k} className="info-row" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                <span className="info-key text-xs">{k}</span>
                <span className="info-val" style={{ fontSize: 18, fontWeight: 700, color: 'var(--color-primary)' }}>{v}</span>
              </div>
            ))}
          </div>

          {/* Category breakdown */}
          {status.ioc_stats?.by_category && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>By Category</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {Object.entries(status.ioc_stats.by_category).map(([cat, count]) => (
                  <div key={cat} className="tag">{cat}: {count}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* IOC match test */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🔍 IOC Match Test</span>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            id="sentinel-match-input"
            type="text"
            value={matchText}
            onChange={(e) => setMatchText(e.target.value)}
            placeholder="Enter text to match against IOC store…"
            style={{
              flex: 1,
              background: 'var(--color-bg-base)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              padding: '10px 14px',
              color: 'var(--color-text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
            }}
            onKeyDown={(e) => e.key === 'Enter' && runMatch()}
          />
          <button
            id="btn-sentinel-match"
            onClick={runMatch}
            type="button"
            style={{
              background: 'var(--color-primary)',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '10px 20px',
              color: 'var(--color-bg-base)',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >Match</button>
        </div>
        {matchResult && (
          <div>
            <div className="text-sm text-muted" style={{ marginBottom: 8 }}>
              {matchResult.count} match{matchResult.count !== 1 ? 'es' : ''} found
            </div>
            {matchResult.matches.map((ioc) => (
              <div key={ioc.ioc_id} style={{
                padding: '10px 14px',
                background: 'var(--color-bg-base)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                marginBottom: 6,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span className="text-sm" style={{ color: SEVERITY_COLORS[ioc.severity] }}>
                    Severity {ioc.severity}/10
                  </span>
                  <span className="tag">{ioc.category}</span>
                </div>
                <div className="text-xs text-mono text-muted">{ioc.pattern}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* IOC Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🗂️ IOC Store ({iocs.length})</span>
        </div>
        <div className="scroll-area">
          {iocs.length === 0 ? (
            <div className="empty-state">
              <Radio size={40} style={{ opacity: 0.2 }} />
              <p>No IOCs loaded yet</p>
            </div>
          ) : iocs.slice(0, 30).map((ioc) => (
            <div key={ioc.ioc_id} style={{
              padding: '10px 0',
              borderBottom: '1px solid var(--color-border)',
              display: 'grid',
              gridTemplateColumns: '60px 1fr auto',
              gap: 12,
              alignItems: 'center',
            }}>
              <span style={{
                fontWeight: 700, fontFamily: 'var(--font-mono)',
                color: SEVERITY_COLORS[ioc.severity],
              }}>{ioc.severity}/10</span>
              <div>
                <div className="text-sm truncate" style={{ color: 'var(--color-text-primary)' }}>
                  {ioc.pattern.slice(0, 70)}
                </div>
                <div className="text-xs text-muted">hits: {ioc.hit_count} · src: {ioc.source_node.slice(0, 12)}</div>
              </div>
              <div className="tag">{ioc.category.replace('_', ' ')}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
