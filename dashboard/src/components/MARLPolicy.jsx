/**
 * @fileoverview MARLPolicy — Q-table heatmap visualizer.
 */

import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
const AGENTS   = ['gateway', 'tool', 'context', 'escalate'];
const ACTIONS  = ['ALLOW', 'RATE_LIMIT', 'QUARANTINE', 'ESCALATE', 'BLOCK'];

const qToColor = (q) => {
  if (q > 5)  return 'rgba(52,211,153,0.7)';
  if (q > 2)  return 'rgba(56,189,248,0.5)';
  if (q > 0)  return 'rgba(167,139,250,0.4)';
  if (q < -3) return 'rgba(244,63,94,0.6)';
  if (q < 0)  return 'rgba(251,146,60,0.4)';
  return 'rgba(255,255,255,0.05)';
};

/**
 * MARLPolicy component.
 * @returns {JSX.Element}
 */
export default function MARLPolicy() {
  const [selectedAgent, setSelectedAgent] = useState('gateway');
  const [heatmap, setHeatmap] = useState([]);
  const [status, setStatus] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [hmResp, stResp] = await Promise.all([
          fetch(`${API_BASE}/api/dashboard/marl/heatmap/${selectedAgent}`),
          fetch(`${API_BASE}/api/dashboard/status`),
        ]);
        if (hmResp.ok) setHeatmap(await hmResp.json());
        if (stResp.ok) setStatus(await stResp.json());
      } catch (_) { /* offline */ }
    };
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [selectedAgent]);

  const marl = status?.marl;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="page-header">
        <h1 className="page-title">MARL Defense Policy</h1>
        <p className="page-subtitle">Q-table heatmap — adaptive defense strategies</p>
      </div>

      {/* Agent selector */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🤖 Agent Selection</span>
          {marl && (
            <span className="tag">{marl.decision_count} total decisions</span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {AGENTS.map((agent) => {
            const agentData = marl?.agents?.find((a) => a.name === agent);
            return (
              <button
                key={agent}
                id={`btn-agent-${agent}`}
                onClick={() => setSelectedAgent(agent)}
                type="button"
                style={{
                  background: selectedAgent === agent
                    ? 'var(--color-primary-glow)'
                    : 'var(--color-bg-card)',
                  border: `1px solid ${selectedAgent === agent
                    ? 'var(--color-primary)' : 'var(--color-border)'}`,
                  borderRadius: 'var(--radius-md)',
                  padding: '10px 16px',
                  color: selectedAgent === agent
                    ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontSize: 13,
                  transition: 'all var(--transition-fast)',
                }}
              >
                {agent}
                {agentData && (
                  <span style={{
                    display: 'block', fontSize: 10,
                    color: 'var(--color-text-muted)',
                    fontWeight: 400,
                  }}>
                    ε={agentData.epsilon.toFixed(3)} · {agentData.q_entries} states
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Action legend */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">📊 Action Legend</span>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {ACTIONS.map((action, i) => (
            <div key={action} style={{
              display: 'flex', alignItems: 'center', gap: 6, fontSize: 12
            }}>
              <div style={{
                width: 16, height: 16, borderRadius: 3,
                background: ['var(--color-success)', 'var(--color-accent)',
                  'var(--color-warning)', 'var(--color-primary)',
                  'var(--color-danger)'][i],
              }} />
              <span className="text-muted">{i}: {action}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Q-table heatmap */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🔥 Q-Value Heatmap — {selectedAgent}</span>
          <span className="tag">{heatmap.length} entries</span>
        </div>

        {heatmap.length === 0 ? (
          <div className="empty-state">
            <div style={{ fontSize: 48, opacity: 0.2 }}>🧠</div>
            <p>No Q-table data yet — send requests to populate.</p>
          </div>
        ) : (
          <div className="scroll-area">
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                    State (band, provider, hour, inj, jb, cot)
                  </th>
                  {ACTIONS.map((a) => (
                    <th key={a} style={{ padding: '6px 8px', color: 'var(--color-text-muted)', fontWeight: 600, minWidth: 70 }}>
                      {a}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {heatmap.slice(0, 20).map((row, i) => (
                  <tr key={i}>
                    <td style={{
                      padding: '6px 10px', fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-secondary)', fontSize: 11,
                    }}>
                      {JSON.stringify(row.state)}
                    </td>
                    {/* Re-fetch all Q values for the same state to show full row */}
                    <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                      <div style={{
                        background: row.action === 0 ? 'rgba(52,211,153,0.3)' : 'transparent',
                        borderRadius: 4, padding: '2px 6px',
                        color: 'var(--color-text-secondary)',
                      }}>
                        {row.action === 0 ? row.q_value.toFixed(2) : '—'}
                      </div>
                    </td>
                    {[1, 2, 3, 4].map((actionIdx) => (
                      <td key={actionIdx} style={{ padding: '6px 8px', textAlign: 'center' }}>
                        <div style={{
                          background: row.action === actionIdx
                            ? qToColor(row.q_value) : 'transparent',
                          borderRadius: 4, padding: '2px 6px',
                          color: 'var(--color-text-secondary)',
                        }}>
                          {row.action === actionIdx ? row.q_value.toFixed(2) : '—'}
                        </div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Reward function explanation */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">📈 Reward Function</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {[
            ['Block confirmed attack', '+10.0', 'var(--color-success)'],
            ['Quarantine real threat', '+5.0',  'var(--color-success)'],
            ['Escalate real threat',   '+2.0',  'var(--color-success)'],
            ['Correct allow (benign)', '+1.0',  'var(--color-primary)'],
            ['Missed attack (allow)',  '-10.0', 'var(--color-danger)'],
            ['False positive block',  '-5.0',  'var(--color-danger)'],
            ['Unnecessary quarantine','-3.0',  'var(--color-warning)'],
            ['Unnecessary escalation','-2.0',  'var(--color-warning)'],
          ].map(([label, reward, color]) => (
            <div key={label} style={{
              display: 'flex', justifyContent: 'space-between',
              padding: '8px 10px',
              background: 'var(--color-bg-panel)',
              borderRadius: 'var(--radius-sm)',
              fontSize: 12,
            }}>
              <span className="text-muted">{label}</span>
              <span style={{ color, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{reward}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
