'use client';

import { useI18n } from '@/i18n/I18nProvider';
import type { MessageKey } from '@/i18n/messages';

export type ThreatAnalysis = {
  verdict: string;
  scanId?: string;
  pending?: boolean;
  providerStatus?: Record<string, { state: string; statusCode: number }>;
  evidence?: Record<string, { verdict: string; vt_score?: number; confidence?: number; model_version?: string }>;
};

export type EmployeeReport = {
  id: string; email: string; url: string; description: string; verdict: string;
  status: string; created_at: string;
  analysis?: ThreatAnalysis;
};

export type FileScan = {
  id: string; file_name: string; file_sha256: string; file_size: number;
  verdict: string; status: 'pending' | 'completed' | 'unknown'; created_at: string;
  analysis: ThreatAnalysis;
};

const STATES = ['ready', 'no_record', 'no_verdict', 'result_unavailable', 'not_configured', 'rate_limited', 'unavailable', 'queued', 'pending', 'expired'];
const PROVIDER_LABELS: Record<string, string> = {
  afferent_ml: 'Afferent ML (Stacker XGBoost)',
  virustotal: 'VirusTotal',
  urlscan: 'urlscan',
};
const PROVIDER_ORDER = ['afferent_ml', 'virustotal', 'urlscan'];

export default function ThreatEvidence({ analysis }: { analysis?: ThreatAnalysis }) {
  const { t } = useI18n();
  const entries = analysis?.providerStatus
    ? Object.entries(analysis.providerStatus)
        .filter(([provider, status]) => !(provider === 'urlscan' && status.state === 'not_configured'))
        .sort(([a], [b]) => (PROVIDER_ORDER.indexOf(a) === -1 ? 99 : PROVIDER_ORDER.indexOf(a)) - (PROVIDER_ORDER.indexOf(b) === -1 ? 99 : PROVIDER_ORDER.indexOf(b)))
    : [];
  return <details className="provider-details" open><summary>{t('ev.title')}</summary>
    {entries.length ? entries.map(([provider, status]) =>
      <p key={provider}><strong>{PROVIDER_LABELS[provider] || provider}</strong>: {status.state === 'invalid_key' ? 'API key rejected (401)' : status.state === 'forbidden' ? 'API access denied (403)' : STATES.includes(status.state) ? t(`ev.state.${status.state}` as MessageKey) : status.state}
        {analysis?.evidence?.[provider] && <> · {analysis.evidence[provider].verdict}
          {analysis.evidence[provider].vt_score != null && <> · {t('ev.detections', { n: analysis.evidence[provider].vt_score ?? 0 })}</>}
          {provider === 'afferent_ml' && analysis.evidence[provider].confidence != null && <> · Confidence {analysis.evidence[provider].confidence}%</>}</>}
      </p>) : <p>{t('ev.none')}</p>}
    <small>{t('ev.note')}</small>
  </details>;
}
