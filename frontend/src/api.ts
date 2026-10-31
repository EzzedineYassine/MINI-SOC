import type {
  AlertDetail,
  AlertDisposition,
  AlertStatus,
  AlertSummary,
  ConnectorExtensionGuide,
  DashboardSummary,
  DetectionRuleMetadata,
  DetectionThresholds,
  ImportResponse,
  NormalizedEvent,
  SampleDataset,
  SourceFormat,
} from './types';

const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, init);
  if (!res.ok) {
    let detail = '';
    try {
      const errBody = await res.json();
      if (errBody && typeof errBody.detail === 'string') {
        detail = errBody.detail;
      }
    } catch {
      // ignore json parse error
    }
    const message = detail
      ? `${detail} (${res.status})`
      : `Request to ${path} failed with HTTP ${res.status}`;
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getDashboard(): Promise<DashboardSummary> {
    return requestJson<DashboardSummary>('/api/dashboard');
  },

  getSamples(): Promise<SampleDataset[]> {
    return requestJson<SampleDataset[]>('/api/samples');
  },

  importSample(sampleId: string): Promise<ImportResponse[]> {
    return requestJson<ImportResponse[]>(`/api/import/sample/${sampleId}`, {
      method: 'POST',
    });
  },

  uploadLogFile(
    file: File,
    sourceFormat?: SourceFormat | '',
    isSimulated: boolean = true
  ): Promise<ImportResponse> {
    const form = new FormData();
    form.append('file', file);
    if (sourceFormat) {
      form.append('source_format', sourceFormat);
    }
    form.append('is_simulated', String(isSimulated));
    return requestJson<ImportResponse>('/api/import/upload', {
      method: 'POST',
      body: form,
    });
  },

  importRawText(payload: {
    filename: string;
    content: string;
    source_format?: SourceFormat;
    is_simulated: boolean;
  }): Promise<ImportResponse> {
    return requestJson<ImportResponse>('/api/import/raw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  },

  listAlerts(filters: {
    start_time?: string;
    end_time?: string;
    host?: string;
    user?: string;
    severity?: string;
    status?: string;
    category?: string;
    search?: string;
  }): Promise<AlertSummary[]> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v && v.trim() !== '') {
        params.set(k, v.trim());
      }
    });
    const qs = params.toString();
    return requestJson<AlertSummary[]>(`/api/alerts${qs ? `?${qs}` : ''}`);
  },

  getAlertDetail(alertId: number): Promise<AlertDetail> {
    return requestJson<AlertDetail>(`/api/alerts/${alertId}`);
  },

  acknowledgeAlert(
    alertId: number,
    analyst: string,
    note?: string
  ): Promise<AlertDetail> {
    return requestJson<AlertDetail>(`/api/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst, note }),
    });
  },

  updateAlert(
    alertId: number,
    payload: {
      status?: AlertStatus;
      disposition?: AlertDisposition;
      disposition_reason?: string;
      analyst: string;
      note?: string;
    }
  ): Promise<AlertDetail> {
    return requestJson<AlertDetail>(`/api/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  },

  addNote(alertId: number, author: string, note: string): Promise<AlertDetail> {
    return requestJson<AlertDetail>(`/api/alerts/${alertId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author, note }),
    });
  },

  listEvents(filters: {
    start_time?: string;
    end_time?: string;
    host?: string;
    user?: string;
    event_type?: string;
    source_ip?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: NormalizedEvent[]; total: number }> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        params.set(k, String(v).trim());
      }
    });
    const qs = params.toString();
    return requestJson<{ items: NormalizedEvent[]; total: number }>(
      `/api/events${qs ? `?${qs}` : ''}`
    );
  },

  getRules(): Promise<DetectionRuleMetadata[]> {
    return requestJson<DetectionRuleMetadata[]>('/api/rules');
  },

  getThresholds(): Promise<DetectionThresholds> {
    return requestJson<DetectionThresholds>('/api/thresholds');
  },

  updateThresholds(thresholds: DetectionThresholds): Promise<{
    thresholds: DetectionThresholds;
    new_alerts_generated: number;
    total_active_alerts: number;
  }> {
    return requestJson('/api/thresholds', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(thresholds),
    });
  },

  resetThresholds(): Promise<{
    thresholds: DetectionThresholds;
    new_alerts_generated: number;
    total_active_alerts: number;
  }> {
    return requestJson('/api/thresholds/reset', {
      method: 'POST',
    });
  },

  getExtensionGuide(): Promise<ConnectorExtensionGuide> {
    return requestJson<ConnectorExtensionGuide>(
      '/api/connectors/extension-guide'
    );
  },

  resetWorkspace(): Promise<{ status: string }> {
    return requestJson<{ status: string }>('/api/workspace/reset', {
      method: 'POST',
    });
  },
};
