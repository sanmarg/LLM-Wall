/**
 * @fileoverview BlockchainLedger — blockchain block explorer component.
 */

import { useState, useEffect } from 'react';
import { Link2, CheckCircle2, XCircle } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

/**
 * BlockchainLedger component.
 * @param {{ compact?: boolean }} props
 * @returns {JSX.Element}
 */
export default function BlockchainLedger({ compact = false }) {
  const [stats, setStats] = useState(null);
  const [blocks, setBlocks] = useState([]);
  const [selected, setSelected] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [statsResp, chainResp] = await Promise.all([
          fetch(`${API_BASE}/api/ledger/stats`),
          fetch(`${API_BASE}/api/ledger/chain?limit=10`),
        ]);
        if (statsResp.ok) setStats(await statsResp.json());
        if (chainResp.ok) setBlocks(await chainResp.json());
      } catch (_) { /* backend offline */ }
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const verifyChain = async () => {
    setVerifying(true);
    try {
      const resp = await fetch(`${API_BASE}/api/ledger/verify`);
      if (resp.ok) setVerifyResult(await resp.json());
    } catch (_) { setVerifyResult({ valid: false }); }
    setVerifying(false);
  };

  const flushLedger = async () => {
    await fetch(`${API_BASE}/api/ledger/flush`, { method: 'POST' });
  };

  const displayBlocks = compact ? blocks.slice(-4).reverse() : [...blocks].reverse();

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">⛓️ Blockchain Ledger</span>
        {!compact && (
          <div className="flex gap-2">
            <button
              className="tag"
              style={{ cursor: 'pointer', border: '1px solid var(--color-border-bright)' }}
              onClick={verifyChain}
              disabled={verifying}
              type="button"
              id="btn-verify-chain"
            >
              {verifying ? <span className="spinner" style={{ width: 12, height: 12 }} /> : '🔍 Verify'}
            </button>
            <button
              className="tag"
              style={{ cursor: 'pointer', color: 'var(--color-accent)', border: '1px solid rgba(167,139,250,0.4)' }}
              onClick={flushLedger}
              type="button"
              id="btn-flush-ledger"
            >
              ⚡ Flush
            </button>
          </div>
        )}
      </div>

      {/* Stats row */}
      {stats && (
        <div className="flex gap-3 mb-4" style={{ flexWrap: 'wrap' }}>
          <div className="info-row" style={{ flex: 1, minWidth: 120 }}>
            <span className="info-key text-xs">Height</span>
            <span className="info-val text-xs text-primary-color">{stats.height}</span>
          </div>
          <div className="info-row" style={{ flex: 1, minWidth: 120 }}>
            <span className="info-key text-xs">Pending</span>
            <span className="info-val text-xs text-warning">{stats.pending_events}</span>
          </div>
          <div className="info-row" style={{ flex: 1, minWidth: 120 }}>
            <span className="info-key text-xs">Records</span>
            <span className="info-val text-xs text-accent">{stats.total_records}</span>
          </div>
        </div>
      )}

      {verifyResult && (
        <div
          className="flex items-center gap-2 mb-4"
          style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-md)',
            background: verifyResult.valid
              ? 'rgba(52,211,153,0.1)' : 'rgba(244,63,94,0.1)',
            border: `1px solid ${verifyResult.valid
              ? 'rgba(52,211,153,0.3)' : 'rgba(244,63,94,0.3)'}`,
          }}
        >
          {verifyResult.valid
            ? <CheckCircle2 size={16} color="var(--color-success)" />
            : <XCircle size={16} color="var(--color-danger)" />}
          <span className="text-sm" style={{
            color: verifyResult.valid
              ? 'var(--color-success)' : 'var(--color-danger)',
          }}>
            Chain {verifyResult.valid ? 'VALID ✅' : 'TAMPERED ❌'}
            — {verifyResult.height} blocks
          </span>
        </div>
      )}

      {/* Block list */}
      <div className="block-list scroll-area">
        {displayBlocks.length === 0 ? (
          <div className="empty-state">
            <Link2 size={32} style={{ opacity: 0.2 }} />
            <p>Genesis block only — no events yet.</p>
          </div>
        ) : displayBlocks.map((block) => (
          <div
            key={block.index}
            id={`block-${block.index}`}
            className="block-item"
            onClick={() => setSelected(selected?.index === block.index ? null : block)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' &&
              setSelected(selected?.index === block.index ? null : block)}
          >
            <div className="block-index">#{block.index}</div>
            <div>
              <div className="block-hash truncate">
                {block.hash?.slice(0, 32)}…
              </div>
              <div className="block-meta">
                {block.timestamp?.slice(0, 19).replace('T', ' ')} ·
                {' '}{block.data?.node_id ?? 'unknown'}
              </div>
            </div>
            <div className="block-events-badge">
              {block.data?.events?.length ?? 0} events
            </div>
          </div>
        ))}
      </div>

      {/* Expanded block detail */}
      {selected && !compact && (
        <div className="code-block mt-4">
          <div style={{ marginBottom: 8, color: 'var(--color-primary)', fontWeight: 600 }}>
            Block #{selected.index} Detail
          </div>
          <div>Merkle Root: {selected.merkle_root?.slice(0, 32)}…</div>
          <div>Nonce: {selected.nonce}</div>
          <div>Prev: {selected.previous_hash?.slice(0, 32)}…</div>
          {selected.data?.events?.map((ev, i) => (
            <div key={i} style={{ marginTop: 6, color: 'var(--color-text-secondary)' }}>
              › [{ev.action}] {ev.primary_category} risk={ev.risk_score}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
