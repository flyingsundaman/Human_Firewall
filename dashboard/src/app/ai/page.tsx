'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Brain, Shield, ShieldAlert, ShieldCheck, RefreshCw, FileText,
  ChevronDown, ChevronUp, AlertTriangle, TrendingUp, TrendingDown,
  Minus, Users, Calendar, Sparkles, Copy, CheckCheck, Loader2,
  ArrowLeft, Fish, Key, UserX, Phone, Paperclip, Bot
} from 'lucide-react';
import Logo from '@/components/Logo';
import '../dashboard.css';
import './ai.css';

/* ── Types ───────────────────────────────────────────────────── */
interface Classification {
  email: string;
  divisi: string;
  risk_level: 'SAFE' | 'VULNERABLE' | 'DANGER';
  risk_score: number;
  primary_risk: string;
  one_line_assessment: string;
  education_tip: string;
}
interface OrgRiskSummary {
  safe_count: number;
  vulnerable_count: number;
  danger_count: number;
  most_at_risk_division: string;
  overall_assessment: string;
}
interface ClassifyAllResult {
  classifications: Classification[];
  org_risk_summary: OrgRiskSummary;
  _generated_at: string;
  _from_cache: boolean;
  _total_users: number;
}
interface UserAnalysis {
  email: string;
  risk_level: 'SAFE' | 'VULNERABLE' | 'DANGER';
  risk_score: number;
  vulnerable_to: string[];
  risk_factors: string[];
  positive_factors: string[];
  education_message: string;
  recommendations: string[];
  priority_action: string;
  trend_assessment: string;
  _raw_context: {
    divisi: string;
    period_days: number;
    summary: Record<string, number | string | null>;
    trend: { direction: string; phishing_clicks_last_7d: number; phishing_clicks_before_7d: number };
  };
  _generated_at: string;
  _from_cache: boolean;
}
interface KeyFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  finding: string;
  detail: string;
}
interface OrgReport {
  report_title: string;
  generated_at: string;
  period_days: number;
  executive_summary: string;
  key_findings: KeyFinding[];
  risk_overview: { overall_risk_level: string; justification: string };
  division_analysis: { divisi: string; risk_level: string; highlight: string }[];
  trend_analysis: string;
  soc_recommendations: { priority: string; action: string; target: string }[];
  positive_highlights: string[];
  next_steps: string;
  _generated_at: string;
  _from_cache: boolean;
}

/* ── Helpers ─────────────────────────────────────────────────── */
const RISK_CONFIG = {
  SAFE:      { label: 'Aman',    color: 'var(--success)',  bg: 'var(--success-glow)',  icon: ShieldCheck },
  VULNERABLE:{ label: 'Rentan',  color: 'var(--warning)',  bg: 'var(--warning-glow)',  icon: ShieldAlert },
  DANGER:    { label: 'Bahaya',  color: 'var(--danger)',   bg: 'var(--danger-glow)',   icon: Shield },
};
const SEVERITY_CONFIG = {
  CRITICAL: { color: 'var(--danger)',   bg: 'var(--danger-glow)' },
  HIGH:     { color: '#f97316',         bg: 'rgba(249,115,22,0.15)' },
  MEDIUM:   { color: 'var(--warning)',  bg: 'var(--warning-glow)' },
  LOW:      { color: 'var(--info)',     bg: 'var(--info-glow)' },
};
const ATTACK_ICONS: Record<string, React.ReactNode> = {
  phishing_email:       <Fish size={13} />,
  credential_harvesting:<Key size={13} />,
  social_engineering:   <UserX size={13} />,
  vishing:              <Phone size={13} />,
  malicious_attachment: <Paperclip size={13} />,
};
const ATTACK_LABELS: Record<string, string> = {
  phishing_email:       'Phishing Email',
  credential_harvesting:'Pencurian Kredensial',
  social_engineering:   'Social Engineering',
  vishing:              'Vishing (Telepon)',
  malicious_attachment: 'Lampiran Berbahaya',
};
const PRIORITY_CONFIG: Record<string, { color: string; bg: string }> = {
  URGENT: { color: 'var(--danger)',  bg: 'var(--danger-glow)' },
  HIGH:   { color: '#f97316',        bg: 'rgba(249,115,22,0.15)' },
  MEDIUM: { color: 'var(--warning)', bg: 'var(--warning-glow)' },
};

function TrendIcon({ direction }: { direction?: string }) {
  if (direction === 'WORSENING') return <TrendingDown size={14} color="var(--danger)" />;
  if (direction === 'IMPROVING') return <TrendingUp size={14} color="var(--success)" />;
  return <Minus size={14} color="var(--text-muted)" />;
}

function getFirstName(email: string): string {
  return email.split('@')[0].split('.')[0];
}
function getInitials(email: string): string {
  const parts = email.split('@')[0].split('.');
  return parts.slice(0, 2).map(p => p[0]?.toUpperCase() || '').join('');
}

/* ── Main Component ───────────────────────────────────────────── */
export default function BehavioralAIPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'report'>('overview');

  // Overview state
  const [classifyData, setClassifyData] = useState<ClassifyAllResult | null>(null);
  const [classifyLoading, setClassifyLoading] = useState(false);
  const [classifyError, setClassifyError] = useState('');

  // User detail state
  const [selectedUser, setSelectedUser] = useState<Classification | null>(null);
  const [userAnalysis, setUserAnalysis] = useState<UserAnalysis | null>(null);
  const [userLoading, setUserLoading] = useState(false);
  const [userDays, setUserDays] = useState(30);

  // Report state
  const [reportData, setReportData] = useState<OrgReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportDays, setReportDays] = useState(7);
  const [reportError, setReportError] = useState('');
  const [copied, setCopied] = useState(false);

  /* Fetch overview */
  const fetchClassifyAll = useCallback(async (forceRefresh = false) => {
    setClassifyLoading(true);
    setClassifyError('');
    try {
      const res = await fetch(`/api/ai/classify?refresh=${forceRefresh}`);
      if (!res.ok) {
        const e = await res.json();
        throw new Error(e.detail || e.error || 'Request gagal');
      }
      const data = await res.json();
      setClassifyData(data);
    } catch (e: unknown) {
      setClassifyError(e instanceof Error ? e.message : String(e));
    } finally {
      setClassifyLoading(false);
    }
  }, []);

  /* Fetch user detail */
  const fetchUserAnalysis = useCallback(async (email: string, days: number, forceRefresh = false) => {
    setUserLoading(true);
    setUserAnalysis(null);
    try {
      const res = await fetch(`/api/ai/user/${encodeURIComponent(email)}?days=${days}&refresh=${forceRefresh}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || data.error || 'Request gagal');
      setUserAnalysis(data);
    } catch (e: unknown) {
      console.error(e);
    } finally {
      setUserLoading(false);
    }
  }, []);

  /* Fetch report */
  const fetchReport = useCallback(async (days: number, forceRefresh = false) => {
    setReportLoading(true);
    setReportError('');
    try {
      const res = await fetch(`/api/ai/report?days=${days}&refresh=${forceRefresh}`);
      if (!res.ok) {
        const e = await res.json();
        throw new Error(e.detail || e.error || 'Request gagal');
      }
      const data = await res.json();
      setReportData(data);
    } catch (e: unknown) {
      setReportError(e instanceof Error ? e.message : String(e));
    } finally {
      setReportLoading(false);
    }
  }, []);

  useEffect(() => { fetchClassifyAll(); }, [fetchClassifyAll]);

  useEffect(() => {
    if (activeTab === 'report' && !reportData) {
      fetchReport(reportDays);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const handleUserSelect = (user: Classification) => {
    setSelectedUser(user);
    setActiveTab('users');
    fetchUserAnalysis(user.email, userDays);
  };

  const handleCopyReport = () => {
    if (!reportData) return;
    const text = [
      reportData.report_title,
      `Periode: ${reportData.period_days} hari`,
      '',
      'EXECUTIVE SUMMARY',
      reportData.executive_summary,
      '',
      'TEMUAN UTAMA',
      ...(reportData.key_findings || []).map(f => `[${f.severity}] ${f.finding}: ${f.detail}`),
      '',
      'REKOMENDASI SOC',
      ...(reportData.soc_recommendations || []).map(r => `[${r.priority}] ${r.action} → ${r.target}`),
    ].join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  /* ── Render ─────────────────────────────────────────── */
  return (
    <div className="ai-page">
      {/* Header */}
      <header className="ai-header">
        <div className="ai-header-left">
          <button className="ai-back-btn" onClick={() => router.push('/admin')}>
            <ArrowLeft size={16} /> Kembali ke SOC
          </button>
          <div className="ai-logo-area">
            <Logo />
            <div className="ai-title-block">
              <div className="ai-badge-label"><Bot size={12} /> AI-Powered</div>
              <h1 className="ai-page-title">Behavioral Analysis</h1>
              <p className="ai-page-subtitle">Analisis perilaku keamanan karyawan menggunakan AI</p>
            </div>
          </div>
        </div>
        <div className="ai-header-right">
          {classifyData && (
            <span className="ai-cache-badge">
              {classifyData._from_cache ? '⚡ Dari Cache' : '🔄 Baru Dianalisis'}
            </span>
          )}
        </div>
      </header>

      {/* Tabs */}
      <nav className="ai-tabs">
        {(['overview', 'users', 'report'] as const).map(tab => (
          <button
            key={tab}
            className={`ai-tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'overview' && <><Users size={14} /> Overview Risiko</>}
            {tab === 'users' && <><Shield size={14} /> Detail User</>}
            {tab === 'report' && <><FileText size={14} /> Laporan</>}
          </button>
        ))}
      </nav>

      <main className="ai-main">

        {/* ── TAB 1: OVERVIEW ─────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="ai-tab-content">
            {/* Toolbar */}
            <div className="ai-toolbar">
              <div className="ai-toolbar-info">
                <Brain size={16} />
                <span>Klasifikasi risiko seluruh karyawan oleh AI</span>
              </div>
              <button
                className="ai-btn-refresh"
                onClick={() => fetchClassifyAll(true)}
                disabled={classifyLoading}
              >
                <RefreshCw size={14} className={classifyLoading ? 'spin' : ''} />
                {classifyLoading ? 'Menganalisis...' : 'Refresh Analisis'}
              </button>
            </div>

            {/* Loading */}
            {classifyLoading && !classifyData && (
              <div className="ai-loading-state">
                <Loader2 size={36} className="spin" />
                <p>AI sedang menganalisis perilaku semua karyawan...</p>
                <span>Proses ini memakan waktu 5-15 detik</span>
              </div>
            )}

            {/* Error */}
            {classifyError && (
              <div className="ai-error-state">
                <AlertTriangle size={24} />
                <div>
                  <strong>Gagal memuat analisis AI</strong>
                  <p>{classifyError}</p>
                  {classifyError.includes('GEMINI_API_KEY') && (
                    <p className="ai-error-hint">
                      💡 Pastikan <code>GEMINI_API_KEY</code> sudah diset di environment variables Flask.
                      Dapatkan key gratis di <a href="https://aistudio.google.com" target="_blank" rel="noreferrer">aistudio.google.com</a>
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Content */}
            {classifyData && (
              <>
                {/* Org Risk Summary */}
                <div className="ai-org-summary">
                  <div className="ai-risk-distribution">
                    {([
                      { key: 'SAFE', count: classifyData.org_risk_summary.safe_count, label: 'Aman' },
                      { key: 'VULNERABLE', count: classifyData.org_risk_summary.vulnerable_count, label: 'Rentan' },
                      { key: 'DANGER', count: classifyData.org_risk_summary.danger_count, label: 'Bahaya' },
                    ] as const).map(({ key, count, label }) => {
                      const cfg = RISK_CONFIG[key];
                      const Icon = cfg.icon;
                      return (
                        <div key={key} className="ai-dist-card" style={{ borderColor: cfg.color, background: cfg.bg }}>
                          <Icon size={24} color={cfg.color} />
                          <div className="ai-dist-count" style={{ color: cfg.color }}>{count}</div>
                          <div className="ai-dist-label">{label}</div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="ai-org-assessment">
                    <div className="ai-assessment-header">
                      <Sparkles size={14} />
                      <span>Penilaian AI</span>
                    </div>
                    <p>{classifyData.org_risk_summary.overall_assessment}</p>
                    <div className="ai-most-risk">
                      <AlertTriangle size={13} color="var(--warning)" />
                      <span>Divisi paling berisiko: <strong>{classifyData.org_risk_summary.most_at_risk_division}</strong></span>
                    </div>
                  </div>
                </div>

                {/* User Cards Grid */}
                <div className="ai-section-label">
                  <Users size={14} />
                  <span>Semua Karyawan ({classifyData._total_users})</span>
                  <span className="ai-section-hint">Klik kartu untuk analisis mendalam</span>
                </div>
                <div className="ai-users-grid">
                  {classifyData.classifications.map(user => {
                    const cfg = RISK_CONFIG[user.risk_level];
                    const Icon = cfg.icon;
                    return (
                      <button
                        key={user.email}
                        className="ai-user-card"
                        style={{ '--risk-color': cfg.color, '--risk-bg': cfg.bg } as React.CSSProperties}
                        onClick={() => handleUserSelect(user)}
                      >
                        <div className="ai-user-card-top">
                          <div className="ai-avatar">{getInitials(user.email)}</div>
                          <div className="ai-user-info">
                            <div className="ai-user-name">{getFirstName(user.email)}</div>
                            <div className="ai-user-email">{user.email}</div>
                            <div className="ai-user-divisi">{user.divisi}</div>
                          </div>
                          <div className="ai-risk-badge" style={{ color: cfg.color, background: cfg.bg }}>
                            <Icon size={12} />
                            {cfg.label}
                          </div>
                        </div>
                        <div className="ai-risk-bar-wrap">
                          <div
                            className="ai-risk-bar"
                            style={{ width: `${user.risk_score}%`, background: cfg.color }}
                          />
                        </div>
                        <div className="ai-user-card-footer">
                          <div className="ai-attack-chip" style={{ color: cfg.color }}>
                            {ATTACK_ICONS[user.primary_risk]}
                            {ATTACK_LABELS[user.primary_risk] || user.primary_risk}
                          </div>
                          <span className="ai-risk-score-label">{user.risk_score}/100</span>
                        </div>
                        <p className="ai-user-assessment">{user.one_line_assessment}</p>
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        )}

        {/* ── TAB 2: USER DETAIL ──────────────────────────── */}
        {activeTab === 'users' && (
          <div className="ai-tab-content">
            {/* User Selector */}
            {classifyData && (
              <div className="ai-user-selector-bar">
                <label className="ai-selector-label">Pilih Karyawan:</label>
                <select
                  className="ai-select"
                  value={selectedUser?.email || ''}
                  onChange={e => {
                    const user = classifyData.classifications.find(u => u.email === e.target.value);
                    if (user) { setSelectedUser(user); fetchUserAnalysis(user.email, userDays); }
                  }}
                >
                  <option value="">-- Pilih karyawan --</option>
                  {classifyData.classifications.map(u => (
                    <option key={u.email} value={u.email}>
                      {u.email} ({RISK_CONFIG[u.risk_level].label})
                    </option>
                  ))}
                </select>
                <select
                  className="ai-select ai-select-sm"
                  value={userDays}
                  onChange={e => {
                    const d = Number(e.target.value);
                    setUserDays(d);
                    if (selectedUser) fetchUserAnalysis(selectedUser.email, d);
                  }}
                >
                  <option value={1}>1 Hari</option>
                  <option value={7}>7 Hari</option>
                  <option value={14}>14 Hari</option>
                  <option value={30}>30 Hari</option>
                </select>
                {selectedUser && (
                  <button
                    className="ai-btn-refresh"
                    onClick={() => fetchUserAnalysis(selectedUser.email, userDays, true)}
                    disabled={userLoading}
                  >
                    <RefreshCw size={13} className={userLoading ? 'spin' : ''} />
                  </button>
                )}
              </div>
            )}

            {/* No user selected */}
            {!selectedUser && (
              <div className="ai-empty-state">
                <Shield size={48} />
                <p>Pilih karyawan dari dropdown di atas</p>
                <span>atau klik kartu user di tab Overview</span>
              </div>
            )}

            {/* Loading */}
            {userLoading && (
              <div className="ai-loading-state">
                <Loader2 size={36} className="spin" />
                <p>AI sedang menganalisis profil {selectedUser?.email}...</p>
              </div>
            )}

            {/* User Analysis Result */}
            {userAnalysis && !userLoading && (
              <div className="ai-user-detail">
                {/* Hero */}
                <div className="ai-user-hero" style={{
                  borderColor: RISK_CONFIG[userAnalysis.risk_level].color,
                  background: RISK_CONFIG[userAnalysis.risk_level].bg,
                }}>
                  <div className="ai-hero-avatar">{getInitials(userAnalysis.email)}</div>
                  <div className="ai-hero-info">
                    <div className="ai-hero-email">{userAnalysis.email}</div>
                    <div className="ai-hero-divisi">{userAnalysis._raw_context?.divisi}</div>
                    <div className="ai-hero-meta">
                      Periode: {userAnalysis._raw_context?.period_days} hari ·
                      <TrendIcon direction={userAnalysis._raw_context?.trend?.direction} />
                      {userAnalysis._raw_context?.trend?.direction === 'WORSENING' ? ' Memburuk' :
                       userAnalysis._raw_context?.trend?.direction === 'IMPROVING' ? ' Membaik' : ' Stabil'}
                    </div>
                  </div>
                  <div className="ai-hero-risk">
                    <div className="ai-risk-level-big" style={{ color: RISK_CONFIG[userAnalysis.risk_level].color }}>
                      {RISK_CONFIG[userAnalysis.risk_level].label.toUpperCase()}
                    </div>
                    <div className="ai-risk-score-big">{userAnalysis.risk_score}<span>/100</span></div>
                  </div>
                </div>

                {/* Attack Vulnerabilities */}
                {userAnalysis.vulnerable_to?.length > 0 && (
                  <div className="ai-detail-section">
                    <h3 className="ai-detail-title"><AlertTriangle size={14} /> Rentan Terhadap</h3>
                    <div className="ai-attack-chips">
                      {userAnalysis.vulnerable_to.map(a => (
                        <span key={a} className="ai-attack-chip-lg" style={{ color: RISK_CONFIG[userAnalysis.risk_level].color, background: RISK_CONFIG[userAnalysis.risk_level].bg }}>
                          {ATTACK_ICONS[a]} {ATTACK_LABELS[a] || a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Education Message */}
                <div className="ai-detail-section ai-education-card">
                  <h3 className="ai-detail-title"><Sparkles size={14} /> Pesan Edukasi Personal</h3>
                  <p className="ai-education-msg">{userAnalysis.education_message}</p>
                </div>

                {/* Priority Action */}
                <div className="ai-detail-section ai-priority-action">
                  <h3 className="ai-detail-title">⚡ Tindakan Prioritas</h3>
                  <p>{userAnalysis.priority_action}</p>
                </div>

                {/* Risk & Positive Factors */}
                <div className="ai-factors-grid">
                  <div className="ai-detail-section">
                    <h3 className="ai-detail-title" style={{ color: 'var(--danger)' }}>⚠ Faktor Risiko</h3>
                    <ul className="ai-factor-list">
                      {(userAnalysis.risk_factors || []).map((f, i) => (
                        <li key={i} className="ai-factor-item ai-factor-risk">{f}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="ai-detail-section">
                    <h3 className="ai-detail-title" style={{ color: 'var(--success)' }}>✓ Faktor Positif</h3>
                    <ul className="ai-factor-list">
                      {(userAnalysis.positive_factors || []).map((f, i) => (
                        <li key={i} className="ai-factor-item ai-factor-positive">{f}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="ai-detail-section">
                  <h3 className="ai-detail-title"><TrendingUp size={14} /> Rekomendasi</h3>
                  <ol className="ai-reco-list">
                    {(userAnalysis.recommendations || []).map((r, i) => (
                      <li key={i} className="ai-reco-item">
                        <span className="ai-reco-num">{i + 1}</span>
                        {r}
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Trend Assessment */}
                <div className="ai-detail-section ai-trend-assess">
                  <h3 className="ai-detail-title">
                    <TrendIcon direction={userAnalysis._raw_context?.trend?.direction} />
                    Asesmen Tren
                  </h3>
                  <p>{userAnalysis.trend_assessment}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── TAB 3: LAPORAN ─────────────────────────────── */}
        {activeTab === 'report' && (
          <div className="ai-tab-content">
            {/* Report toolbar */}
            <div className="ai-toolbar">
              <div className="ai-toolbar-info">
                <FileText size={16} />
                <span>Laporan naratif analisis keamanan organisasi</span>
              </div>
              <div className="ai-report-controls">
                <div className="ai-period-selector">
                  <Calendar size={13} />
                  {([1, 7, 14, 30] as const).map(d => (
                    <button
                      key={d}
                      className={`ai-period-btn ${reportDays === d ? 'active' : ''}`}
                      onClick={() => { setReportDays(d); fetchReport(d); }}
                      disabled={reportLoading}
                    >
                      {d === 1 ? '1H' : d === 7 ? '7H' : d === 14 ? '2M' : '1M'}
                    </button>
                  ))}
                </div>
                <button
                  className="ai-btn-refresh"
                  onClick={() => fetchReport(reportDays, true)}
                  disabled={reportLoading}
                >
                  <RefreshCw size={13} className={reportLoading ? 'spin' : ''} />
                  Generate
                </button>
                {reportData && (
                  <button className="ai-btn-copy" onClick={handleCopyReport}>
                    {copied ? <CheckCheck size={13} /> : <Copy size={13} />}
                    {copied ? 'Tersalin!' : 'Salin'}
                  </button>
                )}
              </div>
            </div>

            {/* Loading */}
            {reportLoading && (
              <div className="ai-loading-state">
                <Loader2 size={36} className="spin" />
                <p>AI sedang menulis laporan {reportDays} hari terakhir...</p>
                <span>Mungkin memakan waktu 10-20 detik</span>
              </div>
            )}

            {/* Error */}
            {reportError && (
              <div className="ai-error-state">
                <AlertTriangle size={24} />
                <div>
                  <strong>Gagal generate laporan</strong>
                  <p>{reportError}</p>
                </div>
              </div>
            )}

            {/* Report Content */}
            {reportData && !reportLoading && (
              <div className="ai-report">
                {/* Report Header */}
                <div className="ai-report-header">
                  <h2 className="ai-report-title">{reportData.report_title}</h2>
                  <div className="ai-report-meta">
                    <span>Periode: {reportData.period_days} hari</span>
                    <span>·</span>
                    <span>{reportData._from_cache ? '⚡ Dari cache' : '🔄 Baru dibuat'}</span>
                  </div>
                </div>

                {/* Risk Overview Banner */}
                {reportData.risk_overview && (() => {
                  const level = reportData.risk_overview.overall_risk_level as keyof typeof SEVERITY_CONFIG;
                  const cfg = SEVERITY_CONFIG[level] || SEVERITY_CONFIG.MEDIUM;
                  return (
                    <div className="ai-report-risk-banner" style={{ borderColor: cfg.color, background: cfg.bg }}>
                      <span className="ai-report-risk-level" style={{ color: cfg.color }}>
                        RISIKO KESELURUHAN: {level}
                      </span>
                      <p>{reportData.risk_overview.justification}</p>
                    </div>
                  );
                })()}

                {/* Executive Summary */}
                <div className="ai-report-section">
                  <h3>📋 Executive Summary</h3>
                  <p>{reportData.executive_summary}</p>
                </div>

                {/* Key Findings */}
                {reportData.key_findings?.length > 0 && (
                  <div className="ai-report-section">
                    <h3>🔍 Temuan Utama</h3>
                    <div className="ai-findings-list">
                      {reportData.key_findings.map((f, i) => {
                        const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.MEDIUM;
                        return (
                          <div key={i} className="ai-finding-card" style={{ borderLeftColor: cfg.color }}>
                            <span className="ai-finding-severity" style={{ color: cfg.color, background: cfg.bg }}>
                              {f.severity}
                            </span>
                            <div>
                              <strong>{f.finding}</strong>
                              <p>{f.detail}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Division Analysis */}
                {reportData.division_analysis?.length > 0 && (
                  <div className="ai-report-section">
                    <h3>🏢 Analisis Per Divisi</h3>
                    <div className="ai-divisi-table">
                      {reportData.division_analysis.map((d, i) => {
                        const level = d.risk_level as 'HIGH' | 'MEDIUM' | 'LOW';
                        const cfg = { HIGH: SEVERITY_CONFIG.HIGH, MEDIUM: SEVERITY_CONFIG.MEDIUM, LOW: { color: 'var(--success)', bg: 'var(--success-glow)' } }[level] || SEVERITY_CONFIG.MEDIUM;
                        return (
                          <div key={i} className="ai-divisi-row">
                            <span className="ai-divisi-name">{d.divisi}</span>
                            <span className="ai-divisi-level" style={{ color: cfg.color, background: cfg.bg }}>{level}</span>
                            <span className="ai-divisi-highlight">{d.highlight}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Trend Analysis */}
                {reportData.trend_analysis && (
                  <div className="ai-report-section">
                    <h3>📈 Analisis Tren</h3>
                    <p>{reportData.trend_analysis}</p>
                  </div>
                )}

                {/* SOC Recommendations */}
                {reportData.soc_recommendations?.length > 0 && (
                  <div className="ai-report-section">
                    <h3>🎯 Rekomendasi untuk SOC</h3>
                    <div className="ai-soc-reco-list">
                      {reportData.soc_recommendations.map((r, i) => {
                        const priority = r.priority as keyof typeof PRIORITY_CONFIG;
                        const cfg = PRIORITY_CONFIG[priority] || PRIORITY_CONFIG.MEDIUM;
                        return (
                          <div key={i} className="ai-soc-reco-card">
                            <span className="ai-soc-priority" style={{ color: cfg.color, background: cfg.bg }}>
                              {priority}
                            </span>
                            <div>
                              <strong>{r.action}</strong>
                              <p className="ai-soc-target">Target: {r.target}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Positive Highlights */}
                {reportData.positive_highlights?.length > 0 && (
                  <div className="ai-report-section">
                    <h3>✅ Hal Positif yang Perlu Dipertahankan</h3>
                    <ul className="ai-positive-list">
                      {reportData.positive_highlights.map((h, i) => (
                        <li key={i}>{h}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Next Steps */}
                {reportData.next_steps && (
                  <div className="ai-report-section ai-next-steps">
                    <h3>🚀 Langkah Selanjutnya (7 Hari)</h3>
                    <p>{reportData.next_steps}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
