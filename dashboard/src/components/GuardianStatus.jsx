/**
 * @fileoverview GuardianStatus — Guardian engine health and agent pipeline.
 */

import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const AGENT_COLORS = {
  intent_agent:    'var(--color-primary)',
  injection_agent: 'var(--color-danger)',
  cot_inspector:   'var(--color-accent)',
  ioc_matcher:     'var(--color-warning)',
};

/**
 * GuardianStatus component.
 * @returns {JSX.Element}
 */
export default function GuardianStatus() {
  const [status, setStatus] = useState(null);
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/dashboard/status`);
        if (resp.ok) setStatus(await resp.json());
      } catch (_) { /* backend offline */ }
    };
    load();
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, []);

  const runTest = async () => {
    if (!testInput.trim()) return;
    setTesting(true);
    setTestResult(null);
    try {
      const resp = await fetch(`${API_BASE}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-LLM-Provider': 'ollama',
        },
        body: JSON.stringify({
          model: 'llama3.2:3b',
          messages: [{ role: 'user', content: testInput }],
        }),
      });
      const data = await resp.json();
      setTestResult({
        status: resp.status,
        riskScore: resp.headers.get('X-Risk-Score') ?? '?',
        action: resp.headers.get('X-Threat-Action') ?? '?',
        data,
      });
    } catch (e) {
      setTestResult({ error: e.message });
    }
    setTesting(false);
  };

  const marl = status?.marl;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <h1 className="page-title">Guardian Engine</h1>
        <p className="page-subtitle">Multi-agent chain-of-thought analyser pipeline</p>
      </div>

      {/* Agent pipeline visualization */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🤖 Agent Pipeline</span>
          <span className="tag">
            {marl?.decision_count ?? 0} decisions
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 12,
        }}>
          {[
            { name: 'intent_agent',    label: 'Intent Classifier',      icon: '🎯', desc: 'Classifies user intent' },
            { name: 'injection_agent', label: 'Injection Detector',     icon: '💉', desc: 'Regex + pattern DB' },
            { name: 'cot_inspector',   label: 'CoT Inspector',          icon: '🔍', desc: 'Chain-of-thought analysis' },
            { name: 'ioc_matcher',     label: 'IOC Matcher',            icon: '🔎', desc: 'Sentinel IOC store' },
          ].map(({ name, label, icon, desc }) => (
            <div key={name} style={{
              background: 'var(--color-bg-panel)',
              border: `1px solid ${AGENT_COLORS[name]}33`,
              borderRadius: 'var(--radius-md)',
              padding: '16px',
              position: 'relative',
              overflow: 'hidden',
            }}>
              <div style={{
                position: 'absolute', top: 0, left: 0, right: 0, height: 2,
                background: AGENT_COLORS[name],
              }} />
              <div style={{ fontSize: 24, marginBottom: 8 }}>{icon}</div>
              <div style={{
                fontSize: 12, fontWeight: 600,
                color: AGENT_COLORS[name],
              }}>{label}</div>
              <div className="text-xs text-muted" style={{ marginTop: 4 }}>{desc}</div>
              <div style={{
                marginTop: 8, display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <div className="status-dot" style={{ background: AGENT_COLORS[name] }} />
                <span className="text-xs text-muted">Active</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* MARL agents */}
      {marl && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">🧠 MARL Defense Agents</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {marl.agents?.map((agent) => (
              <div key={agent.name} style={{
                display: 'grid',
                gridTemplateColumns: '120px 1fr 80px 60px',
                gap: 12,
                alignItems: 'center',
                padding: '10px 0',
                borderBottom: '1px solid var(--color-border)',
              }}>
                <span className="text-sm" style={{ fontWeight: 500 }}>
                  {agent.name}
                </span>
                {/* Epsilon bar */}
                <div style={{
                  background: 'var(--color-bg-base)',
                  borderRadius: 4, height: 6, overflow: 'hidden',
                }}>
                  <div style={{
                    width: `${agent.epsilon * 100}%`,
                    height: '100%',
                    background: 'var(--color-accent)',
                    borderRadius: 4,
                    transition: 'width 0.5s ease',
                    boxShadow: '0 0 6px var(--color-accent-glow)',
                  }} />
                </div>
                <span className="text-xs text-muted text-mono">
                  ε={agent.epsilon.toFixed(3)}
                </span>
                <span className="text-xs text-muted">
                  {agent.q_entries} states
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live test prompt */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🧪 Test Guardian</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <textarea
            id="guardian-test-input"
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            placeholder="Enter a prompt to test against Guardian (e.g. 'Ignore all previous instructions...')"
            style={{
              width: '100%',
              minHeight: 80,
              background: 'var(--color-bg-base)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              padding: '12px',
              color: 'var(--color-text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              resize: 'vertical',
            }}
          />
          <button
            id="btn-test-guardian"
            onClick={runTest}
            disabled={testing || !testInput.trim()}
            type="button"
            style={{
              background: testing
                ? 'var(--color-bg-card)'
                : 'linear-gradient(135deg, var(--color-primary), var(--color-accent))',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '10px 20px',
              color: 'white',
              fontWeight: 600,
              fontSize: 14,
              cursor: testing ? 'not-allowed' : 'pointer',
              alignSelf: 'flex-start',
              transition: 'all var(--transition-fast)',
            }}
          >
            {testing ? '⏳ Analysing…' : '🔍 Analyse Prompt'}
          </button>

          {testResult && (
            <div style={{
              background: 'var(--color-bg-base)',
              border: `1px solid ${
                testResult.status === 403
                  ? 'var(--color-danger)' : 'var(--color-success)'}`,
              borderRadius: 'var(--radius-md)',
              padding: 14,
            }}>
              {testResult.error ? (
                <span className="text-danger">{testResult.error}</span>
              ) : (
                <>
                  <div className="flex gap-3 mb-4">
                    <div>
                      <div className="text-xs text-muted">Status</div>
                      <div className="text-sm" style={{
                        color: testResult.status === 200
                          ? 'var(--color-success)' : 'var(--color-danger)',
                        fontWeight: 600,
                      }}>
                        {testResult.status === 200 ? '✅ ALLOWED' : '🚫 BLOCKED'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted">Risk Score</div>
                      <div className="text-sm text-mono" style={{ fontWeight: 700, color: 'var(--color-primary)' }}>
                        {testResult.riskScore}/100
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted">Action</div>
                      <div className={`threat-badge ${testResult.action}`}>
                        {testResult.action}
                      </div>
                    </div>
                  </div>
                  {testResult.data?.error?.explanation && (
                    <div className="code-block" style={{ fontSize: 11 }}>
                      {testResult.data.error.explanation}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
