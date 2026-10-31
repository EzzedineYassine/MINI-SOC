import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  FileText,
  Filter,
  Info,
  Layers,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  Shield,
  Sliders,
  Terminal,
  Trash2,
  Upload,
} from 'lucide-react';
import { api } from './api';
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

type ActiveTab = 'alerts' | 'events' | 'rules' | 'ingest';

const CATEGORY_LABELS: Record<string, string> = {
  brute_force: 'Brute Force',
  password_spraying: 'Password Spraying',
  suspicious_auth_sequence: 'Suspicious Auth Sequence',
  privileged_account_change: 'Privileged Account Change',
  correlated_compromise: 'Correlated Compromise Chain',
};

const DISPOSITION_LABELS: Record<AlertDisposition, string> = {
  undetermined: 'Undetermined',
  true_positive_malicious: 'True Positive — Malicious Activity',
  true_positive_benign: 'True Positive — Authorized / Benign',
  false_positive: 'False Positive — Benign Trigger',
  educational_simulation: 'Confirmed Lab Simulation Scenario',
};

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('alerts');
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const selectedAlertIdRef = React.useRef<number | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertDetail | null>(null);

  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [eventsTotal, setEventsTotal] = useState<number>(0);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  const [rules, setRules] = useState<DetectionRuleMetadata[]>([]);
  const [thresholds, setThresholds] = useState<DetectionThresholds | null>(null);
  const [privGroupsInput, setPrivGroupsInput] = useState<string>('');

  const [samples, setSamples] = useState<SampleDataset[]>([]);
  const [extensionGuide, setExtensionGuide] =
    useState<ConnectorExtensionGuide | null>(null);
  const [lastImportReports, setLastImportReports] = useState<ImportResponse[]>(
    []
  );

  const [loading, setLoading] = useState<boolean>(false);
  const [bannerMessage, setBannerMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Alert Filters
  const [alertFilters, setAlertFilters] = useState({
    host: '',
    user: '',
    severity: '',
    status: '',
    category: '',
    start_time: '',
    end_time: '',
    search: '',
  });

  // Event Filters
  const [eventFilters, setEventFilters] = useState({
    host: '',
    user: '',
    event_type: '',
    source_ip: '',
    start_time: '',
    end_time: '',
    search: '',
  });

  // Analyst Investigation Form State
  const [analystName, setAnalystName] = useState<string>('SOC Analyst');
  const [statusInput, setStatusInput] = useState<AlertStatus>('new');
  const [dispositionInput, setDispositionInput] =
    useState<AlertDisposition>('undetermined');
  const [dispositionReasonInput, setDispositionReasonInput] =
    useState<string>('');
  const [noteInput, setNoteInput] = useState<string>('');

  // Custom Upload & Raw Log Paste State
  const [uploadFormat, setUploadFormat] = useState<SourceFormat | ''>('');
  const [rawPasteFilename, setRawPasteFilename] =
    useState<string>('custom_auth_snippet.log');
  const [rawPasteFormat, setRawPasteFormat] =
    useState<SourceFormat>('linux_auth');
  const [rawPasteContent, setRawPasteContent] = useState<string>('');

  const refreshCoreData = useCallback(async () => {
    try {
      const [dashData, alertsData, rulesData, threshData] = await Promise.all([
        api.getDashboard(),
        api.listAlerts(alertFilters),
        api.getRules(),
        api.getThresholds(),
      ]);
      setDashboard(dashData);
      setAlerts(alertsData);
      setRules(rulesData);
      setThresholds(threshData);
      setPrivGroupsInput(threshData.monitored_privileged_groups.join(', '));

      if (alertsData.length > 0) {
        const activeId = selectedAlertIdRef.current;
        const currentStillExists = alertsData.some(
          (a) => a.id === activeId
        );
        const targetId = currentStillExists && activeId
          ? activeId
          : alertsData[0].id;
        setSelectedAlertId(targetId);
        selectedAlertIdRef.current = targetId;
        const detail = await api.getAlertDetail(targetId);
        if (selectedAlertIdRef.current === targetId) {
          setSelectedAlert(detail);
          setStatusInput(detail.status);
          setDispositionInput(detail.disposition);
          setDispositionReasonInput(detail.disposition_reason || '');
        }
      } else {
        setSelectedAlertId(null);
        selectedAlertIdRef.current = null;
        setSelectedAlert(null);
      }
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to load SOC data'
      );
    }
  }, [alertFilters]);

  const refreshEvents = useCallback(async () => {
    try {
      const res = await api.listEvents({ ...eventFilters, limit: 300 });
      setEvents(res.items);
      setEventsTotal(res.total);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to load events'
      );
    }
  }, [eventFilters]);

  useEffect(() => {
    refreshCoreData();
    refreshEvents();
    api.getSamples().then(setSamples).catch(() => {});
    api.getExtensionGuide().then(setExtensionGuide).catch(() => {});
  }, [refreshCoreData, refreshEvents]);

  const handleSelectAlert = async (alertId: number) => {
    setSelectedAlertId(alertId);
    selectedAlertIdRef.current = alertId;
    try {
      const detail = await api.getAlertDetail(alertId);
      if (selectedAlertIdRef.current === alertId) {
        setSelectedAlert(detail);
        setStatusInput(detail.status);
        setDispositionInput(detail.disposition);
        setDispositionReasonInput(detail.disposition_reason || '');
      }
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to load alert detail'
      );
    }
  };

  const handleImportSample = async (sampleId: string) => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const reports = await api.importSample(sampleId);
      setLastImportReports(reports);
      const totalImported = reports.reduce(
        (acc, r) => acc + r.imported_events,
        0
      );
      const totalSkipped = reports.reduce(
        (acc, r) => acc + r.duplicate_events_skipped,
        0
      );
      const totalNewAlerts = reports.reduce(
        (acc, r) => acc + r.new_alerts_generated,
        0
      );
      setBannerMessage(
        `Sample import complete: ${totalImported} new events ingested (${totalSkipped} duplicates skipped), ${totalNewAlerts} new alerts generated.`
      );
      await refreshCoreData();
      await refreshEvents();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Sample import failed'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const report = await api.uploadLogFile(file, uploadFormat, true);
      setLastImportReports([report]);
      setBannerMessage(
        `Uploaded ${report.source_name}: ${report.imported_events} events imported, ${report.duplicate_events_skipped} duplicates skipped, ${report.malformed_lines} malformed lines.`
      );
      await refreshCoreData();
      await refreshEvents();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'File upload failed');
    } finally {
      setLoading(false);
      e.target.value = '';
    }
  };

  const handleRawPasteImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawPasteContent.trim()) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const report = await api.importRawText({
        filename: rawPasteFilename || 'manual_snippet.log',
        content: rawPasteContent,
        source_format: rawPasteFormat,
        is_simulated: true,
      });
      setLastImportReports([report]);
      setBannerMessage(
        `Imported snippet (${report.source_name}): ${report.imported_events} events added, ${report.duplicate_events_skipped} duplicates skipped, ${report.malformed_lines} malformed lines.`
      );
      await refreshCoreData();
      await refreshEvents();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Raw log import failed'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAcknowledge = async () => {
    if (!selectedAlert) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const updated = await api.acknowledgeAlert(
        selectedAlert.id,
        analystName || 'SOC Analyst',
        noteInput.trim() || undefined
      );
      setSelectedAlert(updated);
      setStatusInput(updated.status);
      setAlerts((prev) =>
        prev.map((a) => (a.id === updated.id ? { ...a, status: updated.status } : a))
      );
      setNoteInput('');
      setBannerMessage(`Alert #${updated.id} acknowledged by ${analystName}.`);
      await refreshCoreData();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to acknowledge alert'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSaveInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const updated = await api.updateAlert(selectedAlert.id, {
        status: statusInput,
        disposition: dispositionInput,
        disposition_reason: dispositionReasonInput,
        analyst: analystName || 'SOC Analyst',
        note: noteInput.trim() || undefined,
      });
      setSelectedAlert(updated);
      setStatusInput(updated.status);
      setDispositionInput(updated.disposition);
      setDispositionReasonInput(updated.disposition_reason || '');
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === updated.id
            ? { ...a, status: updated.status, disposition: updated.disposition, disposition_reason: updated.disposition_reason }
            : a
        )
      );
      setNoteInput('');
      setBannerMessage(
        `Saved investigation state for Alert #${updated.id} (${updated.status.toUpperCase()}).`
      );
      await refreshCoreData();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to update alert'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleAddNoteOnly = async () => {
    if (!selectedAlert || !noteInput.trim()) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const updated = await api.addNote(
        selectedAlert.id,
        analystName || 'SOC Analyst',
        noteInput.trim()
      );
      setSelectedAlert(updated);
      setNoteInput('');
      setBannerMessage(`Added investigation note to Alert #${updated.id}.`);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to add note');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveThresholds = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!thresholds) return;
    setLoading(true);
    setErrorMessage(null);
    try {
      const groups = privGroupsInput
        .split(',')
        .map((g) => g.trim())
        .filter(Boolean);
      const res = await api.updateThresholds({
        ...thresholds,
        monitored_privileged_groups: groups,
      });
      setThresholds(res.thresholds);
      setBannerMessage(
        `Detection thresholds updated and re-evaluated. Active alerts: ${res.total_active_alerts} (${res.new_alerts_generated} newly triggered).`
      );
      await refreshCoreData();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to update thresholds'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleResetThresholds = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const res = await api.resetThresholds();
      setThresholds(res.thresholds);
      setPrivGroupsInput(res.thresholds.monitored_privileged_groups.join(', '));
      setBannerMessage(
        `Thresholds restored to defaults. Active alerts: ${res.total_active_alerts}.`
      );
      await refreshCoreData();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to reset thresholds'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleResetWorkspace = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      await api.resetWorkspace();
      setLastImportReports([]);
      setBannerMessage(
        'Workspace cleared: all stored events, alerts, and import logs have been reset.'
      );
      await refreshCoreData();
      await refreshEvents();
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to clear workspace'
      );
    } finally {
      setLoading(false);
    }
  };

  const maxBucketTotal =
    dashboard && dashboard.timeline.length > 0
      ? Math.max(...dashboard.timeline.map((b) => b.total), 1)
      : 1;

  return (
    <div className="soc-shell">
      {/* Top Operations Header */}
      <header className="soc-header">
        <div className="soc-brand">
          <div className="soc-logo">
            <Shield size={18} />
          </div>
          <div>
            <h1 className="soc-title">
              MINI-SOC
              <span className="lab-badge">
                SIMULATED DEFENSIVE LAB • OFFLINE
              </span>
            </h1>
            <p className="soc-subtitle">
              Security Monitoring, Detection &amp; Incident Investigation
              Workbench
            </p>
          </div>
        </div>

        <nav className="soc-nav" aria-label="Primary Navigation">
          <button
            type="button"
            className={`nav-tab ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            <AlertTriangle size={14} />
            Alert Queue &amp; Triage
            <span className="nav-count">{dashboard?.total_alerts ?? 0}</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'events' ? 'active' : ''}`}
            onClick={() => setActiveTab('events')}
          >
            <Terminal size={14} />
            Normalized Events
            <span className="nav-count">{dashboard?.total_events ?? 0}</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'rules' ? 'active' : ''}`}
            onClick={() => setActiveTab('rules')}
          >
            <Sliders size={14} />
            Detection Rules &amp; Thresholds
            <span className="nav-count">{rules.length}</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'ingest' ? 'active' : ''}`}
            onClick={() => setActiveTab('ingest')}
          >
            <Upload size={14} />
            Log Ingestion &amp; Connectors
          </button>
        </nav>

        <div className="header-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={loading}
            onClick={() => handleImportSample('all')}
            title="Import supplied synthetic Linux auth.log and Windows Security JSONL datasets"
          >
            <Play size={13} />
            Load Demo Incident Logs
          </button>
          <button
            type="button"
            className="btn btn-danger-subtle"
            disabled={loading}
            onClick={handleResetWorkspace}
            title="Clear all stored events and alerts"
          >
            <Trash2 size={13} />
            Reset Lab
          </button>
        </div>
      </header>

      <main className="soc-main">
        {bannerMessage && (
          <div className="banner-info" role="status">
            <span>{bannerMessage}</span>
            <button
              type="button"
              className="btn"
              onClick={() => setBannerMessage(null)}
            >
              Dismiss
            </button>
          </div>
        )}

        {errorMessage && (
          <div
            className="banner-info"
            style={{ borderLeftColor: 'var(--sev-critical)' }}
            role="alert"
          >
            <span style={{ color: 'var(--sev-critical)' }}>
              {errorMessage}
            </span>
            <button
              type="button"
              className="btn"
              onClick={() => setErrorMessage(null)}
            >
              Dismiss
            </button>
          </div>
        )}

        {/* KPI Overview Strip */}
        <section className="kpi-strip" aria-label="Security Telemetry Summary">
          <div className="kpi-card">
            <div className="kpi-label">
              <span>Normalized Events</span>
              <Database size={13} />
            </div>
            <div className="kpi-value">{dashboard?.total_events ?? 0}</div>
            <div className="kpi-sub">
              <span>
                Hosts: {dashboard?.hosts.length ?? 0} | Users:{' '}
                {dashboard?.users.length ?? 0}
              </span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">
              <span>Total Alerts</span>
              <AlertTriangle size={13} />
            </div>
            <div className="kpi-value">{dashboard?.total_alerts ?? 0}</div>
            <div className="kpi-sub">
              <span style={{ color: 'var(--sev-critical)' }}>
                Crit: {dashboard?.severity_counts.critical ?? 0}
              </span>
              <span style={{ color: 'var(--sev-high)' }}>
                High: {dashboard?.severity_counts.high ?? 0}
              </span>
              <span style={{ color: 'var(--sev-medium)' }}>
                Med: {dashboard?.severity_counts.medium ?? 0}
              </span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">
              <span>Unacknowledged (New)</span>
              <Clock size={13} />
            </div>
            <div
              className="kpi-value"
              style={{
                color:
                  (dashboard?.status_counts.new ?? 0) > 0
                    ? 'var(--sev-high)'
                    : 'var(--text-primary)',
              }}
            >
              {dashboard?.status_counts.new ?? 0}
            </div>
            <div className="kpi-sub">
              <span>
                Ack/In-Progress:{' '}
                {(dashboard?.status_counts.acknowledged ?? 0) +
                  (dashboard?.status_counts.in_progress ?? 0)}
              </span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">
              <span>Resolved / Closed</span>
              <CheckCircle2 size={13} />
            </div>
            <div
              className="kpi-value"
              style={{ color: 'var(--state-resolved)' }}
            >
              {(dashboard?.status_counts.resolved ?? 0) +
                (dashboard?.status_counts.false_positive ?? 0)}
            </div>
            <div className="kpi-sub">
              <span>
                Resolved: {dashboard?.status_counts.resolved ?? 0} | FP:{' '}
                {dashboard?.status_counts.false_positive ?? 0}
              </span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">
              <span>Detection Categories</span>
              <Layers size={13} />
            </div>
            <div className="kpi-value">
              {Object.keys(dashboard?.category_counts ?? {}).length}
            </div>
            <div className="kpi-sub">
              <span>MITRE ATT&amp;CK Mapped Rules Active</span>
            </div>
          </div>
        </section>

        {/* Event Timeline Panel */}
        {dashboard && dashboard.timeline.length > 0 && (
          <section className="panel" aria-label="Event Timeline">
            <div className="panel-header">
              <h2 className="panel-title">
                <Clock size={14} />
                Chronological Event &amp; Indicator Timeline (UTC 10-Minute
                Windows)
              </h2>
              <div
                style={{
                  display: 'flex',
                  gap: '14px',
                  fontSize: '11.5px',
                  color: 'var(--text-secondary)',
                }}
              >
                <span>
                  <strong style={{ color: 'var(--sev-high)' }}>■</strong> Auth
                  / Sudo Failures
                </span>
                <span>
                  <strong style={{ color: 'var(--sev-critical)' }}>■</strong>{' '}
                  Privileged / Account Changes
                </span>
                <span>
                  <strong style={{ color: 'var(--state-resolved)' }}>■</strong>{' '}
                  Successful Logons
                </span>
              </div>
            </div>
            <div className="panel-body">
              <div className="timeline-grid">
                {dashboard.timeline.map((b) => {
                  const failH = Math.round((b.failures / maxBucketTotal) * 58);
                  const privH = Math.round(
                    (b.privileged_events / maxBucketTotal) * 58
                  );
                  const okH = Math.round((b.successes / maxBucketTotal) * 58);
                  return (
                    <div key={b.bucket} className="timeline-col">
                      <div
                        className="timeline-bars"
                        title={`${b.bucket} — Total: ${b.total} (Failures: ${b.failures}, Privileged: ${b.privileged_events}, Successes: ${b.successes})`}
                      >
                        {b.failures > 0 && (
                          <div
                            className="bar-seg bar-fail"
                            style={{ height: `${Math.max(failH, 4)}px` }}
                          />
                        )}
                        {b.privileged_events > 0 && (
                          <div
                            className="bar-seg bar-priv"
                            style={{ height: `${Math.max(privH, 4)}px` }}
                          />
                        )}
                        {b.successes > 0 && (
                          <div
                            className="bar-seg bar-ok"
                            style={{ height: `${Math.max(okH, 4)}px` }}
                          />
                        )}
                      </div>
                      <span className="timeline-label">
                        {b.bucket.slice(11, 16)} UTC
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        )}

        {/* TAB 1: ALERT TRIAGE & INVESTIGATION WORKBENCH */}
        {activeTab === 'alerts' && (
          <>
            {/* Alert Filter Bar */}
            <section className="filter-bar" aria-label="Alert Filters">
              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-search">
                  Search
                </label>
                <input
                  id="filter-alert-search"
                  className="input-control"
                  placeholder="Title, user, IP, MITRE..."
                  value={alertFilters.search}
                  onChange={(e) =>
                    setAlertFilters({ ...alertFilters, search: e.target.value })
                  }
                />
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-severity">
                  Severity
                </label>
                <select
                  id="filter-alert-severity"
                  className="select-control"
                  value={alertFilters.severity}
                  onChange={(e) =>
                    setAlertFilters({
                      ...alertFilters,
                      severity: e.target.value,
                    })
                  }
                >
                  <option value="">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-status">
                  Status
                </label>
                <select
                  id="filter-alert-status"
                  className="select-control"
                  value={alertFilters.status}
                  onChange={(e) =>
                    setAlertFilters({ ...alertFilters, status: e.target.value })
                  }
                >
                  <option value="">All Statuses</option>
                  <option value="new">New</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-category">
                  Detection Category
                </label>
                <select
                  id="filter-alert-category"
                  className="select-control"
                  value={alertFilters.category}
                  onChange={(e) =>
                    setAlertFilters({
                      ...alertFilters,
                      category: e.target.value,
                    })
                  }
                >
                  <option value="">All Categories</option>
                  <option value="correlated_compromise">
                    Correlated Compromise Chain
                  </option>
                  <option value="suspicious_auth_sequence">
                    Suspicious Auth Sequence
                  </option>
                  <option value="privileged_account_change">
                    Privileged Account Change
                  </option>
                  <option value="password_spraying">Password Spraying</option>
                  <option value="brute_force">Brute Force</option>
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-host">
                  Host
                </label>
                <select
                  id="filter-alert-host"
                  className="select-control"
                  value={alertFilters.host}
                  onChange={(e) =>
                    setAlertFilters({ ...alertFilters, host: e.target.value })
                  }
                >
                  <option value="">All Hosts</option>
                  {(dashboard?.hosts ?? []).map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-user">
                  User
                </label>
                <select
                  id="filter-alert-user"
                  className="select-control"
                  value={alertFilters.user}
                  onChange={(e) =>
                    setAlertFilters({ ...alertFilters, user: e.target.value })
                  }
                >
                  <option value="">All Users</option>
                  {(dashboard?.users ?? []).map((u) => (
                    <option key={u} value={u}>
                      {u}
                    </option>
                  ))}
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-start">
                  Start Time (ISO UTC)
                </label>
                <input
                  id="filter-alert-start"
                  className="input-control mono"
                  placeholder="2026-10-30T08:00:00Z"
                  value={alertFilters.start_time}
                  onChange={(e) =>
                    setAlertFilters({
                      ...alertFilters,
                      start_time: e.target.value,
                    })
                  }
                />
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="filter-alert-end">
                  End Time (ISO UTC)
                </label>
                <input
                  id="filter-alert-end"
                  className="input-control mono"
                  placeholder="2026-10-30T09:00:00Z"
                  value={alertFilters.end_time}
                  onChange={(e) =>
                    setAlertFilters({
                      ...alertFilters,
                      end_time: e.target.value,
                    })
                  }
                />
              </div>

              <div
                className="filter-group"
                style={{ justifyContent: 'flex-end', marginTop: '14px' }}
              >
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    setAlertFilters({
                      host: '',
                      user: '',
                      severity: '',
                      status: '',
                      category: '',
                      start_time: '',
                      end_time: '',
                      search: '',
                    })
                  }
                >
                  <RotateCcw size={12} />
                  Clear
                </button>
              </div>
            </section>

            {alerts.length === 0 ? (
              <div className="panel">
                <div className="empty-state">
                  <p style={{ marginBottom: '12px', fontSize: '14px' }}>
                    No alerts match the current filter criteria (or no logs have
                    been imported yet).
                  </p>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => handleImportSample('all')}
                  >
                    <Play size={14} />
                    Import Supplied Synthetic Lab Logs (Linux &amp; Windows)
                  </button>
                </div>
              </div>
            ) : (
              <div className="workbench-grid">
                {/* Left Column: Alert Queue */}
                <section className="panel" aria-label="Alert Queue">
                  <div className="panel-header">
                    <h2 className="panel-title">
                      <AlertTriangle size={14} />
                      Detection Queue ({alerts.length})
                    </h2>
                    <span
                      style={{
                        fontSize: '11.5px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Click any alert to inspect evidence &amp; investigate
                    </span>
                  </div>
                  <div className="data-table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Alert &amp; Scope</th>
                          <th>MITRE</th>
                          <th>Status</th>
                          <th>Last Seen (UTC)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {alerts.map((alert) => {
                          const isSelected = alert.id === selectedAlertId;
                          return (
                            <tr
                              key={alert.id}
                              className={isSelected ? 'selected-row' : ''}
                              onClick={() => handleSelectAlert(alert.id)}
                            >
                              <td>
                                <span
                                  className={`badge sev-${alert.severity}`}
                                >
                                  {alert.severity}
                                </span>
                              </td>
                              <td>
                                <div
                                  style={{
                                    fontWeight: 600,
                                    color: 'var(--text-primary)',
                                    marginBottom: '3px',
                                  }}
                                >
                                  {alert.title}
                                </div>
                                <div
                                  style={{
                                    fontSize: '11.5px',
                                    color: 'var(--text-secondary)',
                                    display: 'flex',
                                    gap: '10px',
                                    flexWrap: 'wrap',
                                  }}
                                >
                                  <span className="mono">
                                    Host: {alert.host}
                                  </span>
                                  {alert.user && (
                                    <span className="mono">
                                      User: {alert.user}
                                    </span>
                                  )}
                                  {alert.source_ip && (
                                    <span className="mono">
                                      IP: {alert.source_ip}
                                    </span>
                                  )}
                                  <span>
                                    {CATEGORY_LABELS[alert.category] ||
                                      alert.category}{' '}
                                    ({alert.evidence_count} events)
                                  </span>
                                </div>
                              </td>
                              <td>
                                <span className="mitre-pill">
                                  {alert.mitre_technique_id}
                                </span>
                              </td>
                              <td>
                                <span
                                  className={`badge status-${alert.status}`}
                                >
                                  {alert.status.replace('_', ' ')}
                                </span>
                              </td>
                              <td className="mono">
                                {alert.last_seen.replace('T', ' ').slice(0, 19)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </section>

                {/* Right Column: Alert Investigation Workbench */}
                <section
                  className="panel"
                  aria-label="Alert Investigation Detail"
                >
                  {selectedAlert ? (
                    <>
                      <div className="panel-header">
                        <div>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '8px',
                              marginBottom: '4px',
                            }}
                          >
                            <span
                              className={`badge sev-${selectedAlert.severity}`}
                            >
                              {selectedAlert.severity}
                            </span>
                            <span
                              className={`badge status-${selectedAlert.status}`}
                            >
                              {selectedAlert.status.replace('_', ' ')}
                            </span>
                            <span className="mono" style={{ color: 'var(--text-muted)' }}>
                              #{selectedAlert.id} • {selectedAlert.rule_id}
                            </span>
                          </div>
                          <h2
                            className="panel-title"
                            style={{ fontSize: '14.5px' }}
                          >
                            {selectedAlert.title}
                          </h2>
                        </div>

                        {selectedAlert.status === 'new' && (
                          <button
                            type="button"
                            className="btn btn-ack"
                            disabled={loading}
                            onClick={handleQuickAcknowledge}
                          >
                            <CheckCircle2 size={14} />
                            Acknowledge Alert
                          </button>
                        )}
                      </div>

                      <div className="panel-body">
                        {/* Key Metadata */}
                        <div className="detail-section">
                          <div className="kv-grid">
                            <div className="kv-item">
                              <span className="kv-key">Host</span>
                              <span className="kv-val">
                                {selectedAlert.host}
                              </span>
                            </div>
                            <div className="kv-item">
                              <span className="kv-key">Target / Actor User</span>
                              <span className="kv-val">
                                {selectedAlert.user || 'N/A'}
                              </span>
                            </div>
                            <div className="kv-item">
                              <span className="kv-key">Source Address</span>
                              <span className="kv-val">
                                {selectedAlert.source_ip || 'Local / Host'}
                              </span>
                            </div>
                            <div className="kv-item">
                              <span className="kv-key">First → Last Seen</span>
                              <span className="kv-val">
                                {selectedAlert.first_seen.slice(11, 19)} →{' '}
                                {selectedAlert.last_seen.slice(11, 19)} UTC
                              </span>
                            </div>
                            <div className="kv-item">
                              <span className="kv-key">Acknowledged By</span>
                              <span className="kv-val">
                                {selectedAlert.acknowledged_by
                                  ? `${selectedAlert.acknowledged_by} (${selectedAlert.acknowledged_at?.slice(11, 19)}Z)`
                                  : 'Unacknowledged'}
                              </span>
                            </div>
                            <div className="kv-item">
                              <span className="kv-key">Disposition</span>
                              <span className="kv-val">
                                {DISPOSITION_LABELS[selectedAlert.disposition]}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Detection Explanation */}
                        <div className="detail-section">
                          <h3 className="section-heading">
                            <Info size={13} />
                            Detection Explanation &amp; Triggering Evidence
                          </h3>
                          <div className="callout-box">
                            <div>{selectedAlert.explanation}</div>
                            {Object.keys(selectedAlert.threshold_snapshot)
                              .length > 0 && (
                              <div
                                className="mono"
                                style={{
                                  marginTop: '6px',
                                  fontSize: '11px',
                                  color: 'var(--text-secondary)',
                                }}
                              >
                                Active Rule Parameters:{' '}
                                {JSON.stringify(
                                  selectedAlert.threshold_snapshot
                                )}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* MITRE ATT&CK Mapping & Rationale */}
                        <div className="detail-section">
                          <h3 className="section-heading">
                            <Shield size={13} />
                            MITRE ATT&amp;CK Mapping &amp; Rationale
                          </h3>
                          <div className="callout-box mitre">
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                marginBottom: '6px',
                                flexWrap: 'wrap',
                              }}
                            >
                              <span className="mitre-pill">
                                {selectedAlert.mitre_technique_id}
                              </span>
                              <strong>
                                {selectedAlert.mitre_technique_name}
                              </strong>
                              <span
                                style={{
                                  fontSize: '11.5px',
                                  color: 'var(--text-secondary)',
                                }}
                              >
                                (Tactic: {selectedAlert.mitre_tactic})
                              </span>
                            </div>
                            <div style={{ color: 'var(--text-secondary)' }}>
                              {selectedAlert.mitre_mapping_rationale}
                            </div>
                          </div>
                        </div>

                        {/* Documented Rule Limitations */}
                        <div className="detail-section">
                          <h3 className="section-heading">
                            <AlertTriangle size={13} />
                            Documented Detection Limitations &amp; Blind Spots
                          </h3>
                          <div className="callout-box limitation">
                            {selectedAlert.rule_limitations}
                          </div>
                        </div>

                        {/* Correlated Evidence Events */}
                        <div className="detail-section">
                          <h3 className="section-heading">
                            <Terminal size={13} />
                            Correlated Underlying Evidence Events (
                            {selectedAlert.evidence_events.length})
                          </h3>
                          <div className="evidence-timeline">
                            {selectedAlert.evidence_events.map((ev) => {
                              const evClass =
                                ev.event_type === 'auth_failure' ||
                                ev.event_type === 'sudo_failure'
                                  ? 'ev-fail'
                                  : ev.event_type === 'auth_success'
                                    ? 'ev-success'
                                    : 'ev-priv';
                              return (
                                <div
                                  key={ev.id}
                                  className={`evidence-item ${evClass}`}
                                >
                                  <div className="evidence-meta">
                                    <span className="mono">
                                      <strong>{ev.timestamp}</strong> •{' '}
                                      {ev.host} • {ev.service}
                                    </span>
                                    <span className="mono">
                                      type={ev.event_type} | user=
                                      {ev.user || '-'} | src=
                                      {ev.source_ip || 'local'}
                                    </span>
                                  </div>
                                  <div className="raw-log-line">
                                    {ev.raw_event}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {/* Analyst Investigation & Disposition Form */}
                        <div className="detail-section">
                          <h3 className="section-heading">
                            <FileText size={13} />
                            Incident Handling Decision, Disposition &amp; Notes
                          </h3>

                          {selectedAlert.notes.length > 0 && (
                            <div className="notes-list">
                              {selectedAlert.notes.map((n) => (
                                <div
                                  key={n.id}
                                  className={`note-card ${
                                    n.action_type === 'status_change'
                                      ? 'audit'
                                      : ''
                                  }`}
                                >
                                  <div className="note-header">
                                    <strong>
                                      {n.author}{' '}
                                      {n.action_type === 'status_change'
                                        ? '(Audit Trail)'
                                        : '(Analyst Note)'}
                                    </strong>
                                    <span className="mono">{n.created_at}</span>
                                  </div>
                                  <div>{n.note}</div>
                                </div>
                              ))}
                            </div>
                          )}

                          <form
                            onSubmit={handleSaveInvestigation}
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              background: 'var(--bg-canvas)',
                              padding: '12px',
                              borderRadius: '5px',
                              border: '1px solid var(--border-subtle)',
                            }}
                          >
                            <div
                              style={{
                                display: 'grid',
                                gridTemplateColumns:
                                  'repeat(auto-fit, minmax(170px, 1fr))',
                                gap: '10px',
                              }}
                            >
                              <div className="filter-group">
                                <label
                                  className="filter-label"
                                  htmlFor="inv-analyst"
                                >
                                  Analyst Name
                                </label>
                                <input
                                  id="inv-analyst"
                                  className="input-control"
                                  value={analystName}
                                  onChange={(e) =>
                                    setAnalystName(e.target.value)
                                  }
                                />
                              </div>

                              <div className="filter-group">
                                <label
                                  className="filter-label"
                                  htmlFor="inv-status"
                                >
                                  Investigation Status
                                </label>
                                <select
                                  id="inv-status"
                                  className="select-control"
                                  value={statusInput}
                                  onChange={(e) =>
                                    setStatusInput(
                                      e.target.value as AlertStatus
                                    )
                                  }
                                >
                                  <option value="new">New</option>
                                  <option value="acknowledged">
                                    Acknowledged
                                  </option>
                                  <option value="in_progress">
                                    In Progress
                                  </option>
                                  <option value="resolved">Resolved</option>
                                  <option value="false_positive">
                                    False Positive
                                  </option>
                                </select>
                              </div>

                              <div className="filter-group">
                                <label
                                  className="filter-label"
                                  htmlFor="inv-disposition"
                                >
                                  Incident Disposition
                                </label>
                                <select
                                  id="inv-disposition"
                                  className="select-control"
                                  value={dispositionInput}
                                  onChange={(e) =>
                                    setDispositionInput(
                                      e.target.value as AlertDisposition
                                    )
                                  }
                                >
                                  <option value="undetermined">
                                    Undetermined
                                  </option>
                                  <option value="true_positive_malicious">
                                    True Positive — Malicious
                                  </option>
                                  <option value="true_positive_benign">
                                    True Positive — Authorized/Benign
                                  </option>
                                  <option value="false_positive">
                                    False Positive
                                  </option>
                                  <option value="educational_simulation">
                                    Confirmed Lab Simulation
                                  </option>
                                </select>
                              </div>
                            </div>

                            <div className="filter-group">
                              <label
                                className="filter-label"
                                htmlFor="inv-reason"
                              >
                                Disposition Summary / Root-Cause Decision
                              </label>
                              <input
                                id="inv-reason"
                                className="input-control"
                                placeholder="e.g., Confirmed SSH brute-force followed by unauthorized sudo group elevation on bastion-01"
                                value={dispositionReasonInput}
                                onChange={(e) =>
                                  setDispositionReasonInput(e.target.value)
                                }
                              />
                            </div>

                            <div className="filter-group">
                              <label
                                className="filter-label"
                                htmlFor="inv-note"
                              >
                                Add Investigation Note
                              </label>
                              <textarea
                                id="inv-note"
                                rows={2}
                                className="textarea-control"
                                placeholder="Document triage findings, correlated evidence, or containment steps..."
                                value={noteInput}
                                onChange={(e) => setNoteInput(e.target.value)}
                              />
                            </div>

                            <div
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                gap: '8px',
                                flexWrap: 'wrap',
                              }}
                            >
                              <button
                                type="button"
                                className="btn"
                                disabled={loading || !noteInput.trim()}
                                onClick={handleAddNoteOnly}
                              >
                                Append Note Only
                              </button>

                              <div style={{ display: 'flex', gap: '8px' }}>
                                {selectedAlert.status !== 'acknowledged' && (
                                  <button
                                    type="button"
                                    className="btn btn-ack"
                                    disabled={loading}
                                    onClick={handleQuickAcknowledge}
                                  >
                                    Acknowledge
                                  </button>
                                )}
                                <button
                                  type="submit"
                                  className="btn btn-resolve"
                                  disabled={loading}
                                >
                                  <CheckCircle2 size={13} />
                                  Save Decision &amp; Status
                                </button>
                              </div>
                            </div>
                          </form>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="empty-state">
                      Select an alert from the queue to inspect its underlying
                      evidence and document investigation decisions.
                    </div>
                  )}
                </section>
              </div>
            )}
          </>
        )}

        {/* TAB 2: NORMALIZED EVENT EXPLORER */}
        {activeTab === 'events' && (
          <>
            <section className="filter-bar" aria-label="Event Explorer Filters">
              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-search">
                  Keyword Search
                </label>
                <input
                  id="ev-search"
                  className="input-control"
                  placeholder="Raw log, user, IP, command..."
                  value={eventFilters.search}
                  onChange={(e) =>
                    setEventFilters({ ...eventFilters, search: e.target.value })
                  }
                />
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-host">
                  Host
                </label>
                <select
                  id="ev-host"
                  className="select-control"
                  value={eventFilters.host}
                  onChange={(e) =>
                    setEventFilters({ ...eventFilters, host: e.target.value })
                  }
                >
                  <option value="">All Hosts</option>
                  {(dashboard?.hosts ?? []).map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-user">
                  User
                </label>
                <select
                  id="ev-user"
                  className="select-control"
                  value={eventFilters.user}
                  onChange={(e) =>
                    setEventFilters({ ...eventFilters, user: e.target.value })
                  }
                >
                  <option value="">All Users</option>
                  {(dashboard?.users ?? []).map((u) => (
                    <option key={u} value={u}>
                      {u}
                    </option>
                  ))}
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-type">
                  Normalized Event Type
                </label>
                <select
                  id="ev-type"
                  className="select-control"
                  value={eventFilters.event_type}
                  onChange={(e) =>
                    setEventFilters({
                      ...eventFilters,
                      event_type: e.target.value,
                    })
                  }
                >
                  <option value="">All Event Types</option>
                  <option value="auth_failure">auth_failure</option>
                  <option value="auth_success">auth_success</option>
                  <option value="sudo_failure">sudo_failure</option>
                  <option value="sudo_command">sudo_command</option>
                  <option value="account_created">account_created</option>
                  <option value="group_membership_change">
                    group_membership_change
                  </option>
                  <option value="privilege_assigned">privilege_assigned</option>
                  <option value="account_locked">account_locked</option>
                </select>
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-ip">
                  Source IP
                </label>
                <input
                  id="ev-ip"
                  className="input-control mono"
                  placeholder="e.g. 203.0.113.88"
                  value={eventFilters.source_ip}
                  onChange={(e) =>
                    setEventFilters({
                      ...eventFilters,
                      source_ip: e.target.value,
                    })
                  }
                />
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-start">
                  Start Time (UTC)
                </label>
                <input
                  id="ev-start"
                  className="input-control mono"
                  placeholder="2026-10-30T08:00:00Z"
                  value={eventFilters.start_time}
                  onChange={(e) =>
                    setEventFilters({
                      ...eventFilters,
                      start_time: e.target.value,
                    })
                  }
                />
              </div>

              <div className="filter-group">
                <label className="filter-label" htmlFor="ev-end">
                  End Time (UTC)
                </label>
                <input
                  id="ev-end"
                  className="input-control mono"
                  placeholder="2026-10-30T08:30:00Z"
                  value={eventFilters.end_time}
                  onChange={(e) =>
                    setEventFilters({
                      ...eventFilters,
                      end_time: e.target.value,
                    })
                  }
                />
              </div>

              <div
                className="filter-group"
                style={{ justifyContent: 'flex-end', marginTop: '14px' }}
              >
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    setEventFilters({
                      host: '',
                      user: '',
                      event_type: '',
                      source_ip: '',
                      start_time: '',
                      end_time: '',
                      search: '',
                    })
                  }
                >
                  <RotateCcw size={12} />
                  Reset
                </button>
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Terminal size={14} />
                  Normalized Event Log Table ({eventsTotal} matching events)
                </h2>
                <span
                  style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}
                >
                  Click any row to inspect structured details &amp; raw event
                </span>
              </div>
              <div className="data-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp (UTC)</th>
                      <th>Host</th>
                      <th>Format</th>
                      <th>Event Type</th>
                      <th>User / Actor</th>
                      <th>Source IP</th>
                      <th>Service &amp; Summary</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev) => {
                      const isExpanded = expandedEventId === ev.id;
                      return (
                        <React.Fragment key={ev.id}>
                          <tr
                            onClick={() =>
                              setExpandedEventId(isExpanded ? null : ev.id)
                            }
                            className={isExpanded ? 'selected-row' : ''}
                          >
                            <td className="mono">{ev.timestamp}</td>
                            <td className="mono">{ev.host}</td>
                            <td>
                              <span className="badge sev-low">
                                {ev.source_format}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`badge ${
                                  ev.event_type.includes('failure')
                                    ? 'sev-high'
                                    : ev.event_type === 'auth_success'
                                      ? 'status-resolved'
                                      : 'sev-critical'
                                }`}
                              >
                                {ev.event_type}
                              </span>
                            </td>
                            <td className="mono">
                              {ev.user || '-'}
                              {ev.actor_user && ev.actor_user !== ev.user
                                ? ` (by ${ev.actor_user})`
                                : ''}
                            </td>
                            <td className="mono">{ev.source_ip || '-'}</td>
                            <td>
                              <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                                [{ev.service}]
                              </span>{' '}
                              {ev.raw_event.slice(0, 95)}
                              {ev.raw_event.length > 95 ? '…' : ''}
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr>
                              <td
                                colSpan={7}
                                style={{
                                  background: 'var(--bg-canvas)',
                                  padding: '12px 16px',
                                }}
                              >
                                <div
                                  style={{
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '8px',
                                  }}
                                >
                                  <div
                                    style={{
                                      display: 'flex',
                                      justifyContent: 'space-between',
                                      fontSize: '11.5px',
                                      color: 'var(--text-secondary)',
                                    }}
                                  >
                                    <span className="mono">
                                      SHA-256 Event Hash (Deduplication Key):{' '}
                                      {ev.event_hash}
                                    </span>
                                    <span className="lab-badge">
                                      {ev.is_simulated
                                        ? 'SIMULATED LAB DATA'
                                        : 'IMPORTED DATA'}
                                    </span>
                                  </div>
                                  <div>
                                    <strong
                                      style={{
                                        fontSize: '11px',
                                        color: 'var(--text-secondary)',
                                      }}
                                    >
                                      STRUCTURED DETAILS:
                                    </strong>
                                    <div className="raw-log-line">
                                      {JSON.stringify(ev.details, null, 2)}
                                    </div>
                                  </div>
                                  <div>
                                    <strong
                                      style={{
                                        fontSize: '11px',
                                        color: 'var(--text-secondary)',
                                      }}
                                    >
                                      RAW SOURCE RECORD:
                                    </strong>
                                    <div className="raw-log-line">
                                      {ev.raw_event}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        {/* TAB 3: DETECTION RULES & CONFIGURABLE THRESHOLDS */}
        {activeTab === 'rules' && thresholds && (
          <div className="workbench-grid">
            {/* Configurable Thresholds Editor */}
            <section className="panel" aria-label="Detection Thresholds">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Settings size={14} />
                  Configurable Detection Thresholds
                </h2>
                <button
                  type="button"
                  className="btn"
                  disabled={loading}
                  onClick={handleResetThresholds}
                >
                  <RotateCcw size={12} />
                  Restore Defaults
                </button>
              </div>
              <div className="panel-body">
                <p
                  style={{
                    marginTop: 0,
                    color: 'var(--text-secondary)',
                    fontSize: '12.5px',
                  }}
                >
                  Thresholds are externalized from rule logic and persisted in
                  SQLite. Saving changes immediately re-evaluates all stored
                  normalized events while preserving alerts that have already
                  been acknowledged or annotated by an analyst.
                </p>

                <form
                  onSubmit={handleSaveThresholds}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: '10px',
                    }}
                  >
                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-bf-count">
                        Brute Force Failure Threshold
                      </label>
                      <input
                        id="th-bf-count"
                        type="number"
                        min={2}
                        max={100}
                        className="input-control mono"
                        value={thresholds.brute_force_failure_threshold}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            brute_force_failure_threshold: Number(
                              e.target.value
                            ),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-bf-win">
                        Brute Force Window (seconds)
                      </label>
                      <input
                        id="th-bf-win"
                        type="number"
                        min={30}
                        max={86400}
                        className="input-control mono"
                        value={thresholds.brute_force_window_seconds}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            brute_force_window_seconds: Number(e.target.value),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-ps-users">
                        Password Spray Distinct Users
                      </label>
                      <input
                        id="th-ps-users"
                        type="number"
                        min={2}
                        max={50}
                        className="input-control mono"
                        value={
                          thresholds.password_spray_distinct_users_threshold
                        }
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            password_spray_distinct_users_threshold: Number(
                              e.target.value
                            ),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-ps-win">
                        Password Spray Window (seconds)
                      </label>
                      <input
                        id="th-ps-win"
                        type="number"
                        min={30}
                        max={86400}
                        className="input-control mono"
                        value={thresholds.password_spray_window_seconds}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            password_spray_window_seconds: Number(
                              e.target.value
                            ),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-seq-count">
                        Failures Before Login (Sequence)
                      </label>
                      <input
                        id="th-seq-count"
                        type="number"
                        min={2}
                        max={50}
                        className="input-control mono"
                        value={
                          thresholds.suspicious_sequence_failures_before_success
                        }
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            suspicious_sequence_failures_before_success: Number(
                              e.target.value
                            ),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-seq-win">
                        Suspicious Sequence Window (seconds)
                      </label>
                      <input
                        id="th-seq-win"
                        type="number"
                        min={30}
                        max={86400}
                        className="input-control mono"
                        value={thresholds.suspicious_sequence_window_seconds}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            suspicious_sequence_window_seconds: Number(
                              e.target.value
                            ),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-sudo-cnt">
                        Sudo Failure Threshold
                      </label>
                      <input
                        id="th-sudo-cnt"
                        type="number"
                        min={1}
                        max={30}
                        className="input-control mono"
                        value={thresholds.sudo_failure_threshold}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            sudo_failure_threshold: Number(e.target.value),
                          })
                        }
                      />
                    </div>

                    <div className="filter-group">
                      <label className="filter-label" htmlFor="th-corr-win">
                        Multi-Stage Correlation Window (s)
                      </label>
                      <input
                        id="th-corr-win"
                        type="number"
                        min={60}
                        max={86400}
                        className="input-control mono"
                        value={thresholds.correlation_window_seconds}
                        onChange={(e) =>
                          setThresholds({
                            ...thresholds,
                            correlation_window_seconds: Number(e.target.value),
                          })
                        }
                      />
                    </div>
                  </div>

                  <div className="filter-group">
                    <label className="filter-label" htmlFor="th-groups">
                      Monitored Privileged Security Groups (comma-separated)
                    </label>
                    <input
                      id="th-groups"
                      className="input-control mono"
                      value={privGroupsInput}
                      onChange={(e) => setPrivGroupsInput(e.target.value)}
                    />
                  </div>

                  <div>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={loading}
                    >
                      <RefreshCw size={13} />
                      Save Thresholds &amp; Re-Evaluate Detections
                    </button>
                  </div>
                </form>
              </div>
            </section>

            {/* Detection Rules Catalog */}
            <section className="panel" aria-label="Detection Rules Catalog">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Shield size={14} />
                  Structured Detection Rules, MITRE Mappings &amp; Limitations
                </h2>
              </div>
              <div
                className="panel-body"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                {rules.map((r) => (
                  <div key={r.rule_id} className="callout-box">
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: '8px',
                        marginBottom: '6px',
                        flexWrap: 'wrap',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                        }}
                      >
                        <span className="mono" style={{ fontWeight: 600 }}>
                          {r.rule_id}
                        </span>
                        <span className={`badge sev-${r.default_severity}`}>
                          {r.default_severity}
                        </span>
                        <span className="mitre-pill">
                          {r.mitre_technique_id} — {r.mitre_technique_name}
                        </span>
                      </div>
                      <span className="mono" style={{ fontSize: '11.5px' }}>
                        Active Alerts: <strong>{r.alert_count}</strong>
                      </span>
                    </div>

                    <div style={{ fontWeight: 600, marginBottom: '4px' }}>
                      {r.rule_name}
                    </div>
                    <p
                      style={{
                        margin: '0 0 8px 0',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {r.description}
                    </p>

                    <div
                      style={{
                        fontSize: '12px',
                        borderTop: '1px solid var(--border-subtle)',
                        paddingTop: '6px',
                        marginTop: '6px',
                      }}
                    >
                      <div>
                        <strong style={{ color: '#8ab0f8' }}>
                          MITRE Mapping Rationale ({r.mitre_tactic}):
                        </strong>{' '}
                        {r.mitre_mapping_rationale}
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        <strong style={{ color: 'var(--sev-medium)' }}>
                          Documented Limitations:
                        </strong>{' '}
                        {r.limitations}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}

        {/* TAB 4: LOG INGESTION, SYNTHETIC PACKS & CONNECTOR EXTENSION GUIDE */}
        {activeTab === 'ingest' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="cards-grid">
              {/* Bundled Synthetic Log Datasets */}
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Play size={14} />
                    Supplied Synthetic Lab Log Packs (Simulated Data)
                  </h2>
                  <span className="lab-badge">SIMULATED DATA</span>
                </div>
                <div
                  className="panel-body"
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                  }}
                >
                  <p
                    style={{
                      margin: 0,
                      color: 'var(--text-secondary)',
                      fontSize: '12.5px',
                    }}
                  >
                    Import realistic synthetic Linux <code>auth.log</code> and
                    Windows Security Event <code>.jsonl</code> exports. Re-importing
                    any file is strictly idempotent: deterministic SHA-256 event
                    fingerprints prevent duplicate events and preserve existing
                    alert investigation states.
                  </p>

                  {samples.map((s) => (
                    <div key={s.id} className="callout-box">
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          marginBottom: '6px',
                          gap: '8px',
                        }}
                      >
                        <strong>{s.title}</strong>
                        <button
                          type="button"
                          className="btn btn-primary"
                          disabled={loading}
                          onClick={() => handleImportSample(s.id)}
                        >
                          <Play size={12} />
                          Import {s.filename}
                        </button>
                      </div>
                      <p
                        style={{
                          margin: '0 0 8px 0',
                          fontSize: '12px',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {s.description}
                      </p>
                      {s.preview_lines.length > 0 && (
                        <div className="raw-log-line">
                          {s.preview_lines.join('\n')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </section>

              {/* Upload Custom Log File or Paste Snippet */}
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Upload size={14} />
                    Import Custom Log File or Paste Raw Log Lines
                  </h2>
                </div>
                <div
                  className="panel-body"
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                  }}
                >
                  <div className="callout-box">
                    <strong style={{ display: 'block', marginBottom: '6px' }}>
                      Upload Log File (.log / .jsonl, max 2 MB / 10,000 lines)
                    </strong>
                    <div
                      style={{
                        display: 'flex',
                        gap: '10px',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                      }}
                    >
                      <select
                        className="select-control"
                        value={uploadFormat}
                        onChange={(e) =>
                          setUploadFormat(e.target.value as SourceFormat | '')
                        }
                      >
                        <option value="">Auto-Detect Format</option>
                        <option value="linux_auth">
                          Linux auth.log / syslog
                        </option>
                        <option value="windows_jsonl">
                          Windows Security JSONL
                        </option>
                      </select>
                      <input
                        type="file"
                        accept=".log,.txt,.jsonl,.json"
                        onChange={handleFileUpload}
                        disabled={loading}
                      />
                    </div>
                  </div>

                  <form
                    onSubmit={handleRawPasteImport}
                    className="callout-box"
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                    }}
                  >
                    <strong>Paste Raw Log Lines for Immediate Parsing</strong>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <input
                        className="input-control mono"
                        value={rawPasteFilename}
                        onChange={(e) => setRawPasteFilename(e.target.value)}
                        placeholder="Filename label"
                      />
                      <select
                        className="select-control"
                        value={rawPasteFormat}
                        onChange={(e) =>
                          setRawPasteFormat(e.target.value as SourceFormat)
                        }
                      >
                        <option value="linux_auth">Linux auth.log</option>
                        <option value="windows_jsonl">Windows JSONL</option>
                      </select>
                    </div>
                    <textarea
                      rows={4}
                      className="textarea-control mono"
                      placeholder="Oct 30 09:15:01 web-01 sshd[3102]: Failed password for invalid user admin from 198.51.100.77 port 52100 ssh2"
                      value={rawPasteContent}
                      onChange={(e) => setRawPasteContent(e.target.value)}
                    />
                    <div>
                      <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={loading || !rawPasteContent.trim()}
                      >
                        Parse &amp; Ingest Snippet
                      </button>
                    </div>
                  </form>

                  {lastImportReports.length > 0 && (
                    <div className="callout-box">
                      <strong style={{ display: 'block', marginBottom: '6px' }}>
                        Latest Import Validation &amp; Deduplication Report
                      </strong>
                      {lastImportReports.map((rep, i) => (
                        <div
                          key={`${rep.source_name}-${i}`}
                          style={{
                            borderTop:
                              i > 0 ? '1px solid var(--border-subtle)' : 'none',
                            paddingTop: i > 0 ? '8px' : 0,
                            marginTop: i > 0 ? '8px' : 0,
                          }}
                        >
                          <div className="mono">
                            <strong>{rep.source_name}</strong> ({rep.source_format}
                            ) — Lines: {rep.total_lines_processed} | Imported:{' '}
                            <span style={{ color: 'var(--state-resolved)' }}>
                              {rep.imported_events}
                            </span>{' '}
                            | Duplicates Skipped:{' '}
                            <span style={{ color: 'var(--sev-medium)' }}>
                              {rep.duplicate_events_skipped}
                            </span>{' '}
                            | Malformed:{' '}
                            <span style={{ color: 'var(--sev-critical)' }}>
                              {rep.malformed_lines}
                            </span>
                          </div>
                          {rep.parse_errors.length > 0 && (
                            <div
                              className="raw-log-line"
                              style={{ marginTop: '6px' }}
                            >
                              {rep.parse_errors
                                .map(
                                  (pe) =>
                                    `Line ${pe.line_number}: ${pe.reason} -> "${pe.raw_excerpt}"`
                                )
                                .join('\n')}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>
            </div>

            {/* Documented Extension Point for Connecting Real Log Sources */}
            {extensionGuide && (
              <section
                className="panel"
                aria-label="Log Source Connector Extension Point"
              >
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Layers size={14} />
                    Documented Extension Point for Real Log Sources (
                    {extensionGuide.extension_interface})
                  </h2>
                  <span className="badge sev-low">
                    Live Endpoint Agent Integrated:{' '}
                    {String(extensionGuide.live_agent_integrated)}
                  </span>
                </div>
                <div className="panel-body">
                  <div
                    className="callout-box limitation"
                    style={{ marginBottom: '12px' }}
                  >
                    <strong>Architectural Transparency Notice:</strong>{' '}
                    {extensionGuide.disclosure}
                  </div>
                  <div className="cards-grid">
                    {extensionGuide.planned_extension_points.map((ext) => (
                      <div key={ext.connector_id} className="callout-box">
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            marginBottom: '6px',
                          }}
                        >
                          <strong>{ext.display_name}</strong>
                          <span className="mono" style={{ fontSize: '11px' }}>
                            {ext.connector_id}
                          </span>
                        </div>
                        <ol
                          style={{
                            margin: 0,
                            paddingLeft: '18px',
                            color: 'var(--text-secondary)',
                            fontSize: '12.5px',
                          }}
                        >
                          {ext.integration_steps.map((step, idx) => (
                            <li key={idx} style={{ marginBottom: '4px' }}>
                              {step}
                            </li>
                          ))}
                        </ol>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
