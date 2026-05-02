/**
 * @fileoverview PatternEvolution — UI for managing the auto-evolving pattern engine.
 */

import { useState, useEffect } from 'react';
import { RefreshCw, Download, Plus, Trash2, Brain, Zap } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

/**
 * PatternEvolution component.
 * @returns {JSX.Element}
 */
export default function PatternEvolution() {
  const [status, setStatus] = useState(null);
  const [patterns, setPatterns] = useState([]);
  const [updating, setUpdating] = useState(false);
  const [updateResult, setUpdateResult] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newPattern, setNewPattern] = useState({
    name: '',
    pattern: '',
    severity: 5,
    category: 'prompt_injection'
  });

  const loadData = async () => {
    try {
      const [statusResp, patternsResp] = await Promise.all([
        fetch(`${API_BASE}/api/patterns/status`),
        fetch(`${API_BASE}/api/patterns/evolved`),
      ]);
      if (statusResp.ok) setStatus(await statusResp.json());
      if (patternsResp.ok) setPatterns(await patternsResp.json());
    } catch (_) { /* backend offline */ }
  };

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 10000);
    return () => clearInterval(id);
  }, []);

  const triggerUpdate = async () => {
    setUpdating(true);
    setUpdateResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/patterns/update`, { method: 'POST' });
      if (resp.ok) {
        const data = await resp.json();
        setUpdateResult(data.summary);
        loadData();
      }
    } catch (e) {
      console.error("Update failed", e);
    }
    setUpdating(false);
  };

  const deletePattern = async (hash) => {
    if (!confirm('Are you sure you want to delete this pattern?')) return;
    try {
      const resp = await fetch(`${API_BASE}/api/patterns/evolved/${hash}`, { method: 'DELETE' });
      if (resp.ok) loadData();
    } catch (e) {
      console.error("Delete failed", e);
    }
  };

  const addCustomPattern = async (e) => {
    e.preventDefault();
    try {
      const resp = await fetch(`${API_BASE}/api/patterns/custom`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newPattern),
      });
      if (resp.ok) {
        setShowAddModal(false);
        setNewPattern({ name: '', pattern: '', severity: 5, category: 'prompt_injection' });
        loadData();
      } else {
        const err = await resp.json();
        alert(err.detail);
      }
    } catch (e) {
      alert("Failed to add pattern");
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="page-header">
        <h1 className="page-title">Pattern Evolution</h1>
        <p className="page-subtitle">Auto-generating and hot-reloading security patterns from global threat feeds</p>
      </div>

      {/* Stats row */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Evolved</div>
          <div className="stat-value accent">{patterns.length}</div>
          <div className="stat-sub">Patterns in evolved DB</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last Synced</div>
          <div className="stat-value" style={{ fontSize: '18px', marginTop: '10px' }}>
            {status?.last_run ? new Date(status.last_run).toLocaleTimeString() : 'Never'}
          </div>
          <div className="stat-sub">Network threat-intel sync</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Feeds</div>
          <div className="stat-value primary">{status?.feeds_configured ?? 0}</div>
          <div className="stat-sub">Active internet sources</div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-3 mb-4">
        <button 
          className="nav-item active" 
          style={{ width: 'auto', borderRadius: 'var(--radius-md)', padding: '10px 20px' }}
          onClick={triggerUpdate}
          disabled={updating}
        >
          {updating ? <RefreshCw className="spinner" size={16} style={{marginRight: 8}} /> : <Download size={16} style={{marginRight: 8}} />}
          {updating ? 'Syncing Feeds...' : 'Sync Global Feeds'}
        </button>
        <button 
          className="nav-item" 
          style={{ width: 'auto', borderRadius: 'var(--radius-md)', padding: '10px 20px', border: '1px solid var(--color-border)' }}
          onClick={() => setShowAddModal(true)}
        >
          <Plus size={16} style={{marginRight: 8}} />
          Add Custom Pattern
        </button>
      </div>

      {updateResult && (
        <div className="card" style={{ border: '1px solid var(--color-success)', background: 'rgba(52, 211, 153, 0.05)' }}>
          <div className="card-header">
            <span className="card-title text-success">Update Successful</span>
          </div>
          <div className="text-sm">
            Added <strong>{updateResult.total_new}</strong> new patterns.
            <ul style={{ marginTop: 8 }}>
              {Object.entries(updateResult.sources).map(([name, count]) => (
                <li key={name}>{name}: +{count}</li>
              ))}
              {updateResult.ioc_promoted > 0 && <li>Promoted from IOCs: +{updateResult.ioc_promoted}</li>}
            </ul>
          </div>
        </div>
      )}

      {/* Pattern List */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Evolved Pattern Database</span>
          <span className="tag">{patterns.length} items</span>
        </div>
        <div className="scroll-area" style={{ maxHeight: '600px' }}>
          {patterns.length === 0 ? (
            <div className="empty-state">
              <Brain size={48} style={{ opacity: 0.2 }} />
              <p>No evolved patterns yet. Trigger a sync to begin.</p>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '11px', color: 'var(--color-text-muted)' }}>PATTERN / SOURCE</th>
                  <th style={{ padding: '12px', textAlign: 'center', fontSize: '11px', color: 'var(--color-text-muted)' }}>SEVERITY</th>
                  <th style={{ padding: '12px', textAlign: 'center', fontSize: '11px', color: 'var(--color-text-muted)' }}>CATEGORY</th>
                  <th style={{ padding: '12px', textAlign: 'right', fontSize: '11px', color: 'var(--color-text-muted)' }}>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {patterns.map((p) => (
                  <tr key={p.hash} style={{ borderBottom: '1px solid var(--color-border)' }}>
                    <td style={{ padding: '12px' }}>
                      <div className="text-sm" style={{ fontWeight: 600 }}>{p.name}</div>
                      <div className="text-xs text-mono text-success" style={{ marginTop: 4, maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.pattern}</div>
                      <div className="text-xs text-muted" style={{ marginTop: 4 }}>Source: {p.source} · {p.auto_generated ? 'Auto-evolved' : 'Manual'}</div>
                    </td>
                    <td style={{ padding: '12px', textAlign: 'center' }}>
                      <span className="glow-text" style={{ fontWeight: 700, color: p.severity > 7 ? 'var(--color-danger)' : 'var(--color-warning)' }}>{p.severity}</span>
                    </td>
                    <td style={{ padding: '12px', textAlign: 'center' }}>
                      <span className="tag">{p.category}</span>
                    </td>
                    <td style={{ padding: '12px', textAlign: 'right' }}>
                      <button 
                        onClick={() => deletePattern(p.hash)}
                        style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
                        className="nav-item:hover"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Add Modal (Simple Overlay) */}
      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card" style={{ width: '500px', border: '1px solid var(--color-primary)' }}>
            <div className="card-header">
              <span className="card-title">Add Custom Security Pattern</span>
            </div>
            <form onSubmit={addCustomPattern} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="flex-col gap-2">
                <label className="text-xs text-muted">Pattern Name</label>
                <input 
                  type="text" 
                  className="code-block" 
                  style={{ width: '100%', color: 'white' }}
                  value={newPattern.name}
                  onChange={e => setNewPattern({...newPattern, name: e.target.value})}
                  required
                />
              </div>
              <div className="flex-col gap-2">
                <label className="text-xs text-muted">Regex Pattern</label>
                <input 
                  type="text" 
                  className="code-block" 
                  style={{ width: '100%', color: 'var(--color-success)' }}
                  value={newPattern.pattern}
                  onChange={e => setNewPattern({...newPattern, pattern: e.target.value})}
                  required
                />
              </div>
              <div className="flex gap-4">
                <div className="flex-col gap-2" style={{ flex: 1 }}>
                  <label className="text-xs text-muted">Severity (1-10)</label>
                  <input 
                    type="number" 
                    min="1" max="10"
                    className="code-block" 
                    style={{ width: '100%', color: 'white' }}
                    value={newPattern.severity}
                    onChange={e => setNewPattern({...newPattern, severity: parseInt(e.target.value)})}
                  />
                </div>
                <div className="flex-col gap-2" style={{ flex: 2 }}>
                  <label className="text-xs text-muted">Category</label>
                  <select 
                    className="code-block" 
                    style={{ width: '100%', color: 'white' }}
                    value={newPattern.category}
                    onChange={e => setNewPattern({...newPattern, category: e.target.value})}
                  >
                    <option value="prompt_injection">Prompt Injection</option>
                    <option value="jailbreak">Jailbreak</option>
                    <option value="tool_abuse">Tool Abuse</option>
                    <option value="llmjacking">LLMjacking</option>
                  </select>
                </div>
              </div>
              <div className="flex gap-3 mt-4" style={{ justifyContent: 'flex-end' }}>
                <button 
                  type="button" 
                  className="nav-item" 
                  style={{ width: 'auto' }}
                  onClick={() => setShowAddModal(false)}
                >Cancel</button>
                <button 
                  type="submit" 
                  className="nav-item active" 
                  style={{ width: 'auto', background: 'var(--color-primary)', color: 'black' }}
                >Add Pattern</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
