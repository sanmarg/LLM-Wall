/**
 * @fileoverview ThreatFeed component — live scrolling blocked request log.
 */

import { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

/** Risk-score colour helper. */
const riskColor = (score) => {
  if (score >= 75) return 'var(--color-danger)';
  if (score >= 50) return 'var(--color-warning)';
  if (score >= 20) return 'var(--color-accent)';
  return 'var(--color-success)';
};

/**
 * ThreatFeed component.
 * @param {{ compact?: boolean }} props
 * @returns {JSX.Element}
 */
export default function ThreatFeed({ compact = false }) {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const feedRef = useRef(null);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/dashboard/threats/recent?limit=50`);
        if (resp.ok) {
          const data = await resp.json();
          setThreats(data.reverse());
        }
      } catch (_) { /* backend not yet running */ }
      setLoading(false);
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title">🔴 Live Threat Feed</span>
        </div>
        <div className="empty-state">
          <div className="spinner" />
          <span className="text-muted text-sm">Connecting to security stream…</span>
        </div>
      </div>
    );
  }

  const displayThreats = compact ? threats.slice(0, 6) : threats;

  return (
    <div className="card" style={compact ? {} : { gridColumn: '1 / -1' }}>
      <div className="card-header">
        <span className="card-title">🔴 Live Threat Feed</span>
        <span className="tag">{threats.length} events</span>
      </div>

      {displayThreats.length === 0 ? (
        <div className="empty-state">
          <CheckCircle size={40} style={{ opacity: 0.3, color: 'var(--color-success)' }} />
          <p>No threats detected — system is clean.</p>
        </div>
      ) : (
        <ul className="threat-feed" ref={feedRef}>
          {displayThreats.map((msg) => {
            const action = msg.payload?.action ?? 'allow';
            const risk   = msg.payload?.risk_score ?? 0;
            const topic  = msg.topic ?? 'unknown';
            const ts     = msg.timestamp
              ? new Date(msg.timestamp).toLocaleTimeString()
              : '—';

            return (
              <li key={msg.message_id} className="threat-item">
                <span className={`threat-badge ${action.replace('_', '-')}`}>
                  {action.replace('_', ' ')}
                </span>
                <div className="threat-info">
                  <div className="threat-topic truncate">{topic}</div>
                  <div className="threat-meta">
                    {msg.payload?.category ?? 'unknown'} · {ts}
                    {msg.payload?.request_id && (
                      <> · ID: {msg.payload.request_id.slice(0, 8)}</>
                    )}
                  </div>
                </div>
                <span
                  className="threat-risk glow-text"
                  style={{ color: riskColor(risk) }}
                >
                  {risk}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
