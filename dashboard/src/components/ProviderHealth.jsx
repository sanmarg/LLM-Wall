/**
 * @fileoverview ProviderHealth — LLM provider connectivity dashboard.
 */

import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const PROVIDERS = [
  {
    id:    'ollama',
    name:  'Ollama',
    icon:  '🦙',
    desc:  'Local inference server',
    color: 'var(--color-success)',
    docs:  'https://ollama.ai',
  },
  {
    id:    'openai',
    name:  'OpenAI',
    icon:  '🤖',
    desc:  'GPT-4o, GPT-4o-mini',
    color: 'var(--color-primary)',
    docs:  'https://platform.openai.com',
  },
  {
    id:    'gemini',
    name:  'Google Gemini',
    icon:  '💎',
    desc:  'Gemini 1.5 Flash / Pro',
    color: 'var(--color-accent)',
    docs:  'https://ai.google.dev',
  },
  {
    id:    'nvidia',
    name:  'NVIDIA NIM',
    icon:  '⚡',
    desc:  'Kimi 2.5 / Mistral via NIM',
    color: 'var(--color-warning)',
    docs:  'https://developer.nvidia.com/nim',
  },
];

/**
 * ProviderHealth component.
 * @returns {JSX.Element}
 */
export default function ProviderHealth() {
  const [health, setHealth] = useState(null);
  const [testProvider, setTestProvider] = useState('ollama');
  const [testPrompt, setTestPrompt] = useState('Say hello in one word.');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/dashboard/providers/health`);
        if (resp.ok) setHealth(await resp.json());
      } catch (_) { /* offline */ }
    };
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    const t0 = performance.now();
    try {
      const resp = await fetch(`${API_BASE}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-LLM-Provider': testProvider,
        },
        body: JSON.stringify({
          model: '',
          messages: [{ role: 'user', content: testPrompt }],
        }),
      });
      const data = await resp.json();
      const latency = Math.round(performance.now() - t0);
      setTestResult({
        ok:      resp.status === 200,
        status:  resp.status,
        latency,
        action:  resp.headers.get('X-Threat-Action') ?? '?',
        risk:    resp.headers.get('X-Risk-Score') ?? '?',
        content: data?.choices?.[0]?.message?.content
          ?? data?.error?.message ?? JSON.stringify(data),
      });
    } catch (e) {
      setTestResult({ ok: false, error: e.message });
    }
    setTesting(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="page-header">
        <h1 className="page-title">Provider Health</h1>
        <p className="page-subtitle">
          LLM provider connectivity — Ollama · OpenAI · Gemini · NVIDIA NIM
        </p>
      </div>

      {/* Provider cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: 16,
      }}>
        {PROVIDERS.map(({ id, name, icon, desc, color }) => {
          const hdStatus = health?.[id];
          const reachable = hdStatus?.reachable;
          const isOnline = reachable === true || reachable === 'configured_via_key';
          const statusLabel = reachable === true
            ? '● Online'
            : reachable === 'configured_via_key'
              ? '⚙ Configured'
              : '○ Offline';

          return (
            <div key={id} className="card" style={{ borderColor: `${color}33` }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>{icon}</div>
              <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 4 }}>{name}</div>
              <div className="text-xs text-muted" style={{ marginBottom: 12 }}>{desc}</div>
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                fontSize: 12, fontWeight: 600,
                color: isOnline ? 'var(--color-success)' : 'var(--color-danger)',
                background: isOnline
                  ? 'rgba(52,211,153,0.1)' : 'rgba(244,63,94,0.1)',
                border: `1px solid ${isOnline
                  ? 'rgba(52,211,153,0.3)' : 'rgba(244,63,94,0.3)'}`,
                borderRadius: 20, padding: '3px 10px',
              }}>
                {statusLabel}
              </div>
              <div style={{ marginTop: 12 }}>
                <button
                  id={`btn-test-${id}`}
                  onClick={() => setTestProvider(id)}
                  type="button"
                  style={{
                    background: testProvider === id ? color : 'transparent',
                    border: `1px solid ${color}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '4px 12px',
                    color: testProvider === id
                      ? 'var(--color-bg-base)' : color,
                    fontSize: 11, fontWeight: 600, cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  {testProvider === id ? '✓ Selected' : 'Select'}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live test */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🧪 Provider Test</span>
          <span className="tag" style={{ color: PROVIDERS.find((p) => p.id === testProvider)?.color }}>
            {testProvider.toUpperCase()}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            id="provider-test-input"
            type="text"
            value={testPrompt}
            onChange={(e) => setTestPrompt(e.target.value)}
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
            onKeyDown={(e) => e.key === 'Enter' && runTest()}
          />
          <button
            id="btn-run-provider-test"
            onClick={runTest}
            disabled={testing}
            type="button"
            style={{
              background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '10px 20px',
              color: 'white',
              fontWeight: 600,
              cursor: testing ? 'not-allowed' : 'pointer',
            }}
          >
            {testing ? '⏳' : '🚀 Test'}
          </button>
        </div>

        {testResult && (
          <div style={{
            background: 'var(--color-bg-base)',
            border: `1px solid ${testResult.ok
              ? 'var(--color-success)' : 'var(--color-danger)'}`,
            borderRadius: 'var(--radius-md)',
            padding: 14,
          }}>
            <div className="flex gap-3 mb-4">
              {[
                ['Status', testResult.status ?? 'Error', testResult.ok ? 'var(--color-success)' : 'var(--color-danger)'],
                ['Latency', testResult.latency ? `${testResult.latency}ms` : '—', 'var(--color-primary)'],
                ['Risk', testResult.risk ?? '?', 'var(--color-warning)'],
                ['Action', testResult.action ?? '?', 'var(--color-accent)'],
              ].map(([k, v, c]) => (
                <div key={k}>
                  <div className="text-xs text-muted">{k}</div>
                  <div className="text-sm text-mono" style={{ color: c, fontWeight: 700 }}>{v}</div>
                </div>
              ))}
            </div>
            {testResult.error && (
              <div className="text-sm text-danger">{testResult.error}</div>
            )}
            {testResult.content && (
              <div className="code-block" style={{ marginTop: 8 }}>
                {testResult.content}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
