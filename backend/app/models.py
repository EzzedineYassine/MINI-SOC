from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SourceFormat(str, Enum):
    LINUX_AUTH = "linux_auth"
    WINDOWS_JSONL = "windows_jsonl"


class EventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILURE = "sudo_failure"
    ACCOUNT_CREATED = "account_created"
    GROUP_MEMBERSHIP_CHANGE = "group_membership_change"
    PRIVILEGE_ASSIGNED = "privilege_assigned"
    ACCOUNT_LOCKED = "account_locked"
    SESSION_EVENT = "session_event"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertDisposition(str, Enum):
    UNDETERMINED = "undetermined"
    TRUE_POSITIVE_MALICIOUS = "true_positive_malicious"
    TRUE_POSITIVE_BENIGN = "true_positive_benign"
    FALSE_POSITIVE = "false_positive"
    EDUCATIONAL_SIMULATION = "educational_simulation"


class DetectionCategory(str, Enum):
    BRUTE_FORCE = "brute_force"
    PASSWORD_SPRAYING = "password_spraying"
    SUSPICIOUS_AUTH_SEQUENCE = "suspicious_auth_sequence"
    PRIVILEGED_ACCOUNT_CHANGE = "privileged_account_change"
    CORRELATED_COMPROMISE = "correlated_compromise"


class NormalizedEventCreate(BaseModel):
    event_hash: str = Field(..., description="Deterministic SHA-256 fingerprint for deduplication")
    timestamp: str = Field(..., description="ISO-8601 UTC normalized timestamp")
    host: str = Field(..., description="Hostname or system identifier")
    source_format: SourceFormat
    event_type: EventType
    user: Optional[str] = Field(None, description="Target or primary account username")
    actor_user: Optional[str] = Field(None, description="Initiating/subject username when applicable")
    source_ip: Optional[str] = Field(None, description="Source IPv4/IPv6 address if available")
    service: str = Field(..., description="Service, daemon, or Windows provider")
    raw_event: str = Field(..., description="Original log line or serialized JSONL record")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured parsed metadata")
    is_simulated: bool = Field(default=True, description="Indicates whether event comes from synthetic lab data")


class NormalizedEvent(NormalizedEventCreate):
    id: int
    imported_at: str


class ParseErrorDetail(BaseModel):
    line_number: int
    raw_excerpt: str
    reason: str


class ParseResult(BaseModel):
    events: List[NormalizedEventCreate] = Field(default_factory=list)
    errors: List[ParseErrorDetail] = Field(default_factory=list)
    total_lines_processed: int = 0


class ImportResponse(BaseModel):
    source_name: str
    source_format: SourceFormat
    is_simulated: bool
    total_lines_processed: int
    imported_events: int
    duplicate_events_skipped: int
    malformed_lines: int
    parse_errors: List[ParseErrorDetail] = Field(default_factory=list)
    new_alerts_generated: int
    total_active_alerts: int


class InvestigationNote(BaseModel):
    id: int
    alert_id: int
    author: str
    note: str
    action_type: str = "note"
    created_at: str


class InvestigationNoteCreate(BaseModel):
    author: str = Field(default="SOC Analyst", min_length=1, max_length=80)
    note: str = Field(..., min_length=1, max_length=4000)


class AlertUpdateRequest(BaseModel):
    status: Optional[AlertStatus] = None
    disposition: Optional[AlertDisposition] = None
    disposition_reason: Optional[str] = Field(default=None, max_length=2000)
    analyst: str = Field(default="SOC Analyst", min_length=1, max_length=80)
    note: Optional[str] = Field(default=None, max_length=4000)


class AlertSummary(BaseModel):
    id: int
    alert_fingerprint: str
    rule_id: str
    rule_name: str
    category: DetectionCategory
    severity: Severity
    status: AlertStatus
    disposition: AlertDisposition
    disposition_reason: Optional[str] = None
    title: str
    explanation: str
    host: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    first_seen: str
    last_seen: str
    evidence_count: int
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_mapping_rationale: str
    rule_limitations: str
    created_at: str
    updated_at: str
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None


class AlertDetail(AlertSummary):
    evidence_events: List[NormalizedEvent] = Field(default_factory=list)
    notes: List[InvestigationNote] = Field(default_factory=list)
    threshold_snapshot: Dict[str, Any] = Field(default_factory=dict)


class DetectionThresholds(BaseModel):
    brute_force_failure_threshold: int = Field(
        default=5,
        ge=2,
        le=100,
        description="Minimum failed login attempts from a source IP or against a user within the window",
    )
    brute_force_window_seconds: int = Field(
        default=300,
        ge=30,
        le=86400,
        description="Sliding time window in seconds for counting repeated failed logins",
    )
    password_spray_distinct_users_threshold: int = Field(
        default=3,
        ge=2,
        le=50,
        description="Minimum distinct target accounts failing authentication from the same source IP within the window",
    )
    password_spray_window_seconds: int = Field(
        default=600,
        ge=30,
        le=86400,
        description="Sliding time window in seconds for password spraying detection",
    )
    suspicious_sequence_failures_before_success: int = Field(
        default=3,
        ge=2,
        le=50,
        description="Minimum failed login attempts immediately preceding a successful login within the sequence window",
    )
    suspicious_sequence_window_seconds: int = Field(
        default=600,
        ge=30,
        le=86400,
        description="Maximum seconds between first failure cluster and subsequent successful authentication",
    )
    sudo_failure_threshold: int = Field(
        default=2,
        ge=1,
        le=30,
        description="Minimum consecutive unauthorized sudo attempts before triggering a privilege escalation alert",
    )
    correlation_window_seconds: int = Field(
        default=1800,
        ge=60,
        le=86400,
        description="Maximum seconds between a suspicious authentication sequence and privileged account change on the same host",
    )
    monitored_privileged_groups: List[str] = Field(
        default=["sudo", "wheel", "root", "admin", "Administrators", "Domain Admins", "Enterprise Admins", "Backup Operators"],
        description="Security-sensitive group names that trigger privileged account modification alerts",
    )


class DetectionRuleMetadata(BaseModel):
    rule_id: str
    rule_name: str
    category: DetectionCategory
    default_severity: Severity
    description: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_mapping_rationale: str
    limitations: str
    configurable_parameters: List[str]
    current_parameter_values: Dict[str, Any]
    alert_count: int = 0
