/**
 * @fileoverview Root application component for LLM Wall Dashboard.
 * Manages navigation state and SSE live feed connection.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Activity, Link2, Cpu, Database, Radio, BarChart2, ChevronRight, Zap
} from 'lucide-react';
import ThreatFeed from './components/ThreatFeed.jsx';
import GuardianStatus from './components/GuardianStatus.jsx';
import BlockchainLedger from './components/BlockchainLedger.jsx';
import SentinelMesh from './components/SentinelMesh.jsx';
import MARLPolicy from './components/MARLPolicy.jsx';
import ProviderHealth from './components/ProviderHealth.jsx';
import PatternEvolution from './components/PatternEvolution.jsx';

/** @type {Array<{id: string, label: string, icon: JSX.Element}>} */
const NAV_ITEMS = [
  { id: 'overview',    label: 'Overview',      icon: <Activity size={16} /> },
  { id: 'threats',     label: 'Threat Feed',   icon: <Shield size={16} /> },
  { id: 'guardian',    label: 'Guardian',       icon: <Cpu size={16} /> },
  { id: 'patterns',    label: 'Patterns',       icon: <Zap size={16} /> },
  { id: 'ledger',      label: 'Blockchain',     icon: <Link2 size={16} /> },
  { id: 'sentinel',    label: 'Sentinel Mesh',  icon: <Radio size={16} /> },
  { id: 'marl',        label: 'MARL Policy',    icon: <BarChart2 size={16} /> },
  { id: 'providers',   label: 'Providers',      icon: <Database size={16} /> },
];

/**
 * Root App component.
 * @returns {JSX.Element}
 */
export default function App() {
  const [activeView, setActiveView] = useState('overview');
  const [liveData, setLiveData] = useState(null);
  const [connected, setConnected] = useState(false);

  /** Connect to server-sent events stream. */
  useEffect(() => {
    const es = new EventSource('/api/dashboard/stream/events');
    es.onopen = () => setConnected(true);
    es.onmessage = (e) => {
      try {
        setLiveData(JSON.parse(e.data));
      } catch (_) { /* ignore malformed frames */ }
    };
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, []);

  const recentThreats = liveData?.recent_threats ?? [];
  const blockedCount = recentThreats.filter(
    (t) => t.payload?.action === 'block'
  ).length;
  const totalPublished = liveData?.bus_published ?? 0;

  return (
    <div className="app-layout">
      {/* ── Header ── */}
      <header className="app-header">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <span className="brand-name">LLM Wall</span>
          <span className="brand-badge">v1.0</span>
        </div>

        <div className="header-status">
          <div className="status-pill">
            <div className={`status-dot ${connected ? '' : 'danger'}`} />
            {connected ? 'Live' : 'Connecting…'}
          </div>
          <div className="status-pill">
            <div className="status-dot warning" />
            {liveData?.sentinel_iocs ?? '—'} IOCs
          </div>
          <div className="status-pill">
            <div className="status-dot" />
            Block #{liveData?.chain_height ?? '—'}
          </div>
        </div>
      </header>

      {/* ── Sidebar Navigation ── */}
      <nav className="app-sidebar">
        <p className="nav-label">Navigation</p>
        {NAV_ITEMS.map(({ id, label, icon }) => (
          <button
            key={id}
            id={`nav-${id}`}
            className={`nav-item ${activeView === id ? 'active' : ''}`}
            onClick={() => setActiveView(id)}
            type="button"
          >
            {icon}
            {label}
            {activeView === id && <ChevronRight size={12} style={{ marginLeft: 'auto' }} />}
          </button>
        ))}

        {/* Mini stats in sidebar */}
        <p className="nav-label" style={{ marginTop: '24px' }}>Live Stats</p>
        <div style={{ padding: '0 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div className="info-row">
            <span className="info-key text-xs">MARL Decisions</span>
            <span className="info-val text-xs text-primary-color">
              {liveData?.marl_decisions ?? '—'}
            </span>
          </div>
          <div className="info-row">
            <span className="info-key text-xs">Bus Messages</span>
            <span className="info-val text-xs text-accent">
              {totalPublished}
            </span>
          </div>
          <div className="info-row">
            <span className="info-key text-xs">Blocked (recent)</span>
            <span className="info-val text-xs text-danger">
              {blockedCount}
            </span>
          </div>
        </div>
      </nav>

      {/* ── Main Content ── */}
      <main className="app-main">
        {activeView === 'overview' && (
          <OverviewPage liveData={liveData} setActiveView={setActiveView} />
        )}
        {activeView === 'threats' && <ThreatFeed />}
        {activeView === 'guardian' && <GuardianStatus />}
        {activeView === 'patterns' && <PatternEvolution />}
        {activeView === 'ledger' && <BlockchainLedger />}
        {activeView === 'sentinel' && <SentinelMesh />}
        {activeView === 'marl' && <MARLPolicy />}
        {activeView === 'providers' && <ProviderHealth />}
      </main>
    </div>
  );
}

/**
 * Overview page with top-level KPI cards.
 * @param {{ liveData: object|null, setActiveView: function }} props
 * @returns {JSX.Element}
 */
function OverviewPage({ liveData, setActiveView }) {
  const stats = [
    {
      label:    'Chain Height',
      value:    liveData?.chain_height ?? 0,
      sub:      'Blocks mined',
      cls:      '',
      view:     'ledger',
    },
    {
      label:    'Active IOCs',
      value:    liveData?.sentinel_iocs ?? 0,
      sub:      'Indicators of Compromise',
      cls:      'danger',
      view:     'sentinel',
    },
    {
      label:    'MARL Decisions',
      value:    liveData?.marl_decisions ?? 0,
      sub:      'Adaptive defense actions',
      cls:      'accent',
      view:     'marl',
    },
    {
      label:    'Bus Messages',
      value:    liveData?.bus_published ?? 0,
      sub:      'A2A signals published',
      cls:      'success',
      view:     'threats',
    },
  ];

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Security Overview</h1>
        <p className="page-subtitle">
          Real-time telemetry from all LLM Wall subsystems
        </p>
      </div>

      {/* KPI Stats */}
      <div className="stats-grid">
        {stats.map(({ label, value, sub, cls, view }) => (
          <div
            key={label}
            className="stat-card"
            style={{ cursor: 'pointer' }}
            onClick={() => setActiveView(view)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && setActiveView(view)}
          >
            <div className="stat-label">{label}</div>
            <div className={`stat-value ${cls}`}>{value.toLocaleString()}</div>
            <div className="stat-sub">{sub}</div>
          </div>
        ))}
      </div>

      {/* Two-column section: Live Threats + Quick Actions */}
      <div className="section-grid">
        <ThreatFeed compact />
        <BlockchainLedger compact />
      </div>
    </>
  );
}
