export type SourceFormat = 'linux_auth' | 'windows_jsonl';

export type EventType =
  | 'auth_failure'
  | 'auth_success'
  | 'sudo_command'
  | 'sudo_failure'
  | 'account_created'
  | 'group_membership_change'
  | 'privilege_assigned'
  | 'account_locked'
  | 'session_event';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type AlertStatus =
  | 'new'
  | 'acknowledged'
  | 'in_progress'
  | 'resolved'
  | 'false_positive';

export type AlertDisposition =
  | 'undetermined'
  | 'true_positive_malicious'
  | 'true_positive_benign'
  | 'false_positive'
  | 'educational_simulation';

export type DetectionCategory =
  | 'brute_force'
  | 'password_spraying'
  | 'suspicious_auth_sequence'
  | 'privileged_account_change'
  | 'correlated_compromise';

export interface NormalizedEvent {
  id: number;
  event_hash: string;
  timestamp: string;
  host: string;
  source_format: SourceFormat;
  event_type: EventType;
  user: string | null;
  actor_user: string | null;
  source_ip: string | null;
  service: string;
  raw_event: string;
  details: Record<string, unknown>;
  is_simulated: boolean;
  imported_at: string;
}

export interface ParseErrorDetail {
  line_number: number;
  raw_excerpt: string;
  reason: string;
}

export interface ImportResponse {
  source_name: string;
  source_format: SourceFormat;
  is_simulated: boolean;
  total_lines_processed: number;
  imported_events: number;
  duplicate_events_skipped: number;
  malformed_lines: number;
  parse_errors: ParseErrorDetail[];
  new_alerts_generated: number;
  total_active_alerts: number;
}

export interface InvestigationNote {
  id: number;
  alert_id: number;
  author: string;
  note: string;
  action_type: string;
  created_at: string;
}

export interface AlertSummary {
  id: number;
  alert_fingerprint: string;
  rule_id: string;
  rule_name: string;
  category: DetectionCategory;
  severity: Severity;
  status: AlertStatus;
  disposition: AlertDisposition;
  disposition_reason: string | null;
  title: string;
  explanation: string;
  host: string;
  user: string | null;
  source_ip: string | null;
  first_seen: string;
  last_seen: string;
  evidence_count: number;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_mapping_rationale: string;
  rule_limitations: string;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}

export interface AlertDetail extends AlertSummary {
  evidence_events: NormalizedEvent[];
  notes: InvestigationNote[];
  threshold_snapshot: Record<string, unknown>;
}

export interface DetectionThresholds {
  brute_force_failure_threshold: number;
  brute_force_window_seconds: number;
  password_spray_distinct_users_threshold: number;
  password_spray_window_seconds: number;
  suspicious_sequence_failures_before_success: number;
  suspicious_sequence_window_seconds: number;
  sudo_failure_threshold: number;
  correlation_window_seconds: number;
  monitored_privileged_groups: string[];
}

export interface DetectionRuleMetadata {
  rule_id: string;
  rule_name: string;
  category: DetectionCategory;
  default_severity: Severity;
  description: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_mapping_rationale: string;
  limitations: string;
  configurable_parameters: string[];
  current_parameter_values: Record<string, unknown>;
  alert_count: number;
}

export interface TimelineBucket {
  bucket: string;
  total: number;
  failures: number;
  successes: number;
  privileged_events: number;
}

export interface ImportHistoryEntry {
  id: number;
  source_name: string;
  source_format: string;
  is_simulated: boolean;
  total_lines: number;
  imported_events: number;
  duplicate_events: number;
  malformed_lines: number;
  new_alerts: number;
  imported_at: string;
}

export interface DashboardSummary {
  total_events: number;
  total_alerts: number;
  severity_counts: Record<Severity, number>;
  status_counts: Record<AlertStatus, number>;
  category_counts: Record<string, number>;
  event_type_counts: Record<string, number>;
  hosts: string[];
  users: string[];
  timeline: TimelineBucket[];
  import_history: ImportHistoryEntry[];
}

export interface SampleDataset {
  id: string;
  title: string;
  filename: string;
  source_format: SourceFormat;
  is_simulated: boolean;
  description: string;
  available: boolean;
  preview_lines: string[];
}

export interface ConnectorExtensionGuide {
  environment_mode: string;
  live_agent_integrated: boolean;
  disclosure: string;
  extension_interface: string;
  active_connectors: {
    connector_id: string;
    display_name: string;
    status: string;
    mode: string;
  }[];
  planned_extension_points: {
    connector_id: string;
    display_name: string;
    status: string;
    integration_steps: string[];
  }[];
}
