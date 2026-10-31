from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import (
    DetectionCategory,
    DetectionRuleMetadata,
    DetectionThresholds,
    EventType,
    NormalizedEvent,
    Severity,
)


@dataclass
class AlertCandidate:
    alert_fingerprint: str
    rule_id: str
    rule_name: str
    category: DetectionCategory
    severity: Severity
    title: str
    explanation: str
    host: str
    user: Optional[str]
    source_ip: Optional[str]
    first_seen: str
    last_seen: str
    evidence_event_ids: List[int]
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_mapping_rationale: str
    rule_limitations: str
    threshold_snapshot: Dict[str, Any]


def parse_iso_utc(ts_str: str) -> datetime:
    cleaned = ts_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_alert_fingerprint(
    rule_id: str,
    host: str,
    entity_key: str,
    first_event_hash: str,
) -> str:
    raw = f"{rule_id}|{host.lower()}|{entity_key.lower()}|{first_event_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


RULE_CATALOG: List[Dict[str, Any]] = [
    {
        "rule_id": "RULE-BF-001",
        "rule_name": "Repeated Failed Authentication Attempts (Single-Target Brute Force)",
        "category": DetectionCategory.BRUTE_FORCE,
        "default_severity": Severity.MEDIUM,
        "description": (
            "Detects repeated failed login attempts against a specific account from a single source IP "
            "(or local terminal) within a configurable sliding time window."
        ),
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "mitre_mapping_rationale": (
            "Mapped to T1110.001 because a high concentration of authentication failures targeting a single "
            "account within a short window is a primary indicator of automated password guessing against SSH or Windows logon services."
        ),
        "limitations": (
            "Cannot distinguish a misconfigured service or script using stale credentials from an external attacker "
            "without asset context. Low-and-slow guessing spaced beyond brute_force_window_seconds or distributed across "
            "many source IPs will not cross this per-source threshold."
        ),
        "configurable_parameters": [
            "brute_force_failure_threshold",
            "brute_force_window_seconds",
        ],
    },
    {
        "rule_id": "RULE-PS-002",
        "rule_name": "Multi-Account Password Spraying Activity",
        "category": DetectionCategory.PASSWORD_SPRAYING,
        "default_severity": Severity.HIGH,
        "description": (
            "Detects a single source IP failing authentication across multiple distinct user accounts on the same "
            "host within the configured password spraying time window."
        ),
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110.003",
        "mitre_technique_name": "Brute Force: Password Spraying",
        "mitre_mapping_rationale": (
            "Mapped to T1110.003 because adversaries commonly test one or two common passwords across many distinct "
            "usernames from a single origin to avoid triggering per-account lockout policies."
        ),
        "limitations": (
            "Corporate NAT gateways, VPN concentrators, or shared jump hosts where several users legitimately mistype "
            "passwords within the same window can produce benign triggers. Attackers rotating proxy IPs per request will evade single-IP grouping."
        ),
        "configurable_parameters": [
            "password_spray_distinct_users_threshold",
            "password_spray_window_seconds",
        ],
    },
    {
        "rule_id": "RULE-SEQ-003",
        "rule_name": "Suspicious Authentication Sequence (Failures Followed by Successful Logon)",
        "category": DetectionCategory.SUSPICIOUS_AUTH_SEQUENCE,
        "default_severity": Severity.HIGH,
        "description": (
            "Detects a sequence of repeated failed login attempts immediately followed by a successful authentication "
            "for the same user or from the same source IP within the sequence window."
        ),
        "mitre_tactic": "Initial Access / Credential Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts (Post-Brute Force Compromise)",
        "mitre_mapping_rationale": (
            "Mapped to T1078 (paired with T1110) because a burst of failed authentications culminating in an accepted "
            "login strongly suggests an adversary succeeded in guessing or cycling through credentials to obtain a valid session."
        ),
        "limitations": (
            "A legitimate user who forgets or mistypes their password multiple times before entering the correct credential "
            "can trigger this rule if suspicious_sequence_failures_before_success is set low. Analysts should verify source IP reputation and post-login commands."
        ),
        "configurable_parameters": [
            "suspicious_sequence_failures_before_success",
            "suspicious_sequence_window_seconds",
        ],
    },
    {
        "rule_id": "RULE-PRIV-004",
        "rule_name": "Privileged Account or Security Group Modification",
        "category": DetectionCategory.PRIVILEGED_ACCOUNT_CHANGE,
        "default_severity": Severity.HIGH,
        "description": (
            "Detects creation of new local/domain user accounts, additions of accounts to monitored privileged groups "
            "(such as sudo, wheel, Administrators, Domain Admins), or repeated unauthorized sudo escalation attempts."
        ),
        "mitre_tactic": "Persistence / Privilege Escalation",
        "mitre_technique_id": "T1098",
        "mitre_technique_name": "Account Manipulation & Local Account Creation (T1136.001)",
        "mitre_mapping_rationale": (
            "Mapped to T1098 and T1136.001 because attackers routinely create secondary accounts or grant administrative "
            "group membership to compromised accounts to establish persistent privileged access."
        ),
        "limitations": (
            "Authorized administrative maintenance (onboarding staff, configuration management runs) produces identical "
            "events in system logs. Requires analyst correlation with approved change tickets or preceding login anomalies."
        ),
        "configurable_parameters": [
            "monitored_privileged_groups",
            "sudo_failure_threshold",
        ],
    },
    {
        "rule_id": "RULE-CORR-005",
        "rule_name": "Correlated Compromise Chain: Suspicious Logon to Privilege Escalation",
        "category": DetectionCategory.CORRELATED_COMPROMISE,
        "default_severity": Severity.CRITICAL,
        "description": (
            "Correlates a suspicious authentication sequence (brute-force/spray followed by login) with subsequent "
            "privileged account creation, security group modification, or administrative command execution on the same host."
        ),
        "mitre_tactic": "Privilege Escalation / Persistence",
        "mitre_technique_id": "T1548.003",
        "mitre_technique_name": "Abuse Elevation Control Mechanism (Multi-Stage Intrusion Chain)",
        "mitre_mapping_rationale": (
            "Mapped to T1548.003 / T1098 because linking initial credential compromise (T1110 -> T1078) with immediate "
            "privilege elevation or account manipulation on the same host confirms multi-stage post-exploitation behavior."
        ),
        "limitations": (
            "Correlation is scoped to a single host within correlation_window_seconds. Lateral movement to a different "
            "hostname or dormant attackers waiting longer than the correlation window before escalating privileges will not be linked by this rule."
        ),
        "configurable_parameters": [
            "suspicious_sequence_failures_before_success",
            "correlation_window_seconds",
            "monitored_privileged_groups",
        ],
    },
]


def detect_brute_force(
    events: List[NormalizedEvent], thresholds: DetectionThresholds
) -> List[AlertCandidate]:
    """RULE-BF-001: Detect repeated failed logins for the same (host, user, source_ip) within window."""
    rule_meta = RULE_CATALOG[0]
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = {}
    for ev in events:
        if ev.event_type == EventType.AUTH_FAILURE:
            key = (
                ev.host,
                (ev.user or "unknown"),
                (ev.source_ip or "local"),
            )
            grouped.setdefault(key, []).append(ev)

    candidates: List[AlertCandidate] = []
    window_sec = thresholds.brute_force_window_seconds
    min_failures = thresholds.brute_force_failure_threshold

    for (host, user, source_ip), ev_list in grouped.items():
        if len(ev_list) < min_failures:
            continue

        # Sliding window evaluation to find maximal qualifying cluster
        i = 0
        emitted_event_ids: Set[int] = set()
        while i < len(ev_list):
            start_dt = parse_iso_utc(ev_list[i].timestamp)
            cluster: List[NormalizedEvent] = [ev_list[i]]
            j = i + 1
            while j < len(ev_list):
                curr_dt = parse_iso_utc(ev_list[j].timestamp)
                if (curr_dt - start_dt).total_seconds() <= window_sec:
                    cluster.append(ev_list[j])
                    j += 1
                else:
                    break

            if len(cluster) >= min_failures and not all(e.id in emitted_event_ids for e in cluster):
                for e in cluster:
                    emitted_event_ids.add(e.id)
                severity = (
                    Severity.HIGH
                    if len(cluster) >= min_failures * 2
                    else Severity.MEDIUM
                )
                first_ev = cluster[0]
                last_ev = cluster[-1]
                duration = int(
                    (
                        parse_iso_utc(last_ev.timestamp)
                        - parse_iso_utc(first_ev.timestamp)
                    ).total_seconds()
                )
                fp = build_alert_fingerprint(
                    rule_meta["rule_id"],
                    host,
                    f"{user}:{source_ip}",
                    first_ev.event_hash,
                )
                candidates.append(
                    AlertCandidate(
                        alert_fingerprint=fp,
                        rule_id=rule_meta["rule_id"],
                        rule_name=rule_meta["rule_name"],
                        category=rule_meta["category"],
                        severity=severity,
                        title=f"Repeated failed logins ({len(cluster)} attempts) for '{user}' on {host} from {source_ip}",
                        explanation=(
                            f"Observed {len(cluster)} failed authentication attempts targeting account '{user}' "
                            f"on host '{host}' originating from '{source_ip}' within {duration} seconds "
                            f"(configured threshold: >= {min_failures} failures within {window_sec}s)."
                        ),
                        host=host,
                        user=user if user != "unknown" else None,
                        source_ip=source_ip if source_ip != "local" else None,
                        first_seen=first_ev.timestamp,
                        last_seen=last_ev.timestamp,
                        evidence_event_ids=[e.id for e in cluster],
                        mitre_tactic=rule_meta["mitre_tactic"],
                        mitre_technique_id=rule_meta["mitre_technique_id"],
                        mitre_technique_name=rule_meta["mitre_technique_name"],
                        mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                        rule_limitations=rule_meta["limitations"],
                        threshold_snapshot={
                            "brute_force_failure_threshold": min_failures,
                            "brute_force_window_seconds": window_sec,
                        },
                    )
                )
                i = j
            else:
                i += 1

    return candidates


def detect_password_spraying(
    events: List[NormalizedEvent], thresholds: DetectionThresholds
) -> List[AlertCandidate]:
    """RULE-PS-002: Detect single source IP failing logins across multiple distinct accounts on a host."""
    rule_meta = RULE_CATALOG[1]
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = {}
    for ev in events:
        if ev.event_type == EventType.AUTH_FAILURE and ev.source_ip and ev.user:
            grouped.setdefault((ev.host, ev.source_ip), []).append(ev)

    candidates: List[AlertCandidate] = []
    window_sec = thresholds.password_spray_window_seconds
    min_users = thresholds.password_spray_distinct_users_threshold

    for (host, source_ip), ev_list in grouped.items():
        i = 0
        emitted_event_ids: Set[int] = set()
        while i < len(ev_list):
            start_dt = parse_iso_utc(ev_list[i].timestamp)
            cluster: List[NormalizedEvent] = [ev_list[i]]
            j = i + 1
            while j < len(ev_list):
                curr_dt = parse_iso_utc(ev_list[j].timestamp)
                if (curr_dt - start_dt).total_seconds() <= window_sec:
                    cluster.append(ev_list[j])
                    j += 1
                else:
                    break

            distinct_users = sorted({e.user for e in cluster if e.user})
            if len(distinct_users) >= min_users and not all(
                e.id in emitted_event_ids for e in cluster
            ):
                for e in cluster:
                    emitted_event_ids.add(e.id)
                first_ev = cluster[0]
                last_ev = cluster[-1]
                duration = int(
                    (
                        parse_iso_utc(last_ev.timestamp)
                        - parse_iso_utc(first_ev.timestamp)
                    ).total_seconds()
                )
                fp = build_alert_fingerprint(
                    rule_meta["rule_id"],
                    host,
                    source_ip,
                    first_ev.event_hash,
                )
                user_list_str = ", ".join(distinct_users[:8])
                candidates.append(
                    AlertCandidate(
                        alert_fingerprint=fp,
                        rule_id=rule_meta["rule_id"],
                        rule_name=rule_meta["rule_name"],
                        category=rule_meta["category"],
                        severity=Severity.HIGH,
                        title=f"Password spraying from {source_ip} across {len(distinct_users)} accounts on {host}",
                        explanation=(
                            f"Source IP '{source_ip}' failed authentication against {len(distinct_users)} distinct user "
                            f"accounts ({user_list_str}) on host '{host}' across {len(cluster)} total attempts within {duration} seconds "
                            f"(configured threshold: >= {min_users} distinct users within {window_sec}s)."
                        ),
                        host=host,
                        user=distinct_users[0] if distinct_users else None,
                        source_ip=source_ip,
                        first_seen=first_ev.timestamp,
                        last_seen=last_ev.timestamp,
                        evidence_event_ids=[e.id for e in cluster],
                        mitre_tactic=rule_meta["mitre_tactic"],
                        mitre_technique_id=rule_meta["mitre_technique_id"],
                        mitre_technique_name=rule_meta["mitre_technique_name"],
                        mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                        rule_limitations=rule_meta["limitations"],
                        threshold_snapshot={
                            "password_spray_distinct_users_threshold": min_users,
                            "password_spray_window_seconds": window_sec,
                        },
                    )
                )
                i = j
            else:
                i += 1

    return candidates


def detect_suspicious_auth_sequences(
    events: List[NormalizedEvent], thresholds: DetectionThresholds
) -> List[AlertCandidate]:
    """RULE-SEQ-003: Detect repeated failed logins followed by a successful login within window."""
    rule_meta = RULE_CATALOG[2]
    min_failures = thresholds.suspicious_sequence_failures_before_success
    window_sec = thresholds.suspicious_sequence_window_seconds

    by_host: Dict[str, List[NormalizedEvent]] = {}
    for ev in events:
        if ev.event_type in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
            by_host.setdefault(ev.host, []).append(ev)

    candidates: List[AlertCandidate] = []
    for host, host_events in by_host.items():
        for idx, ev in enumerate(host_events):
            if ev.event_type != EventType.AUTH_SUCCESS:
                continue

            success_dt = parse_iso_utc(ev.timestamp)
            preceding_failures: List[NormalizedEvent] = []
            for prev in host_events[:idx]:
                if prev.event_type != EventType.AUTH_FAILURE:
                    continue
                prev_dt = parse_iso_utc(prev.timestamp)
                delta = (success_dt - prev_dt).total_seconds()
                if 0 <= delta <= window_sec:
                    same_user = bool(ev.user and prev.user and ev.user.lower() == prev.user.lower())
                    same_ip = bool(ev.source_ip and prev.source_ip and ev.source_ip == prev.source_ip)
                    if same_user or same_ip:
                        preceding_failures.append(prev)

            if len(preceding_failures) >= min_failures:
                evidence = [*preceding_failures, ev]
                first_ev = evidence[0]
                duration = int(
                    (
                        success_dt - parse_iso_utc(first_ev.timestamp)
                    ).total_seconds()
                )
                fp = build_alert_fingerprint(
                    rule_meta["rule_id"],
                    host,
                    f"{ev.user or 'unknown'}:{ev.source_ip or 'local'}",
                    ev.event_hash,
                )
                candidates.append(
                    AlertCandidate(
                        alert_fingerprint=fp,
                        rule_id=rule_meta["rule_id"],
                        rule_name=rule_meta["rule_name"],
                        category=rule_meta["category"],
                        severity=Severity.HIGH,
                        title=f"Suspicious login success for '{ev.user}' on {host} after {len(preceding_failures)} failures",
                        explanation=(
                            f"Account '{ev.user}' successfully authenticated on '{host}' from '{ev.source_ip or 'local'}' "
                            f"immediately following {len(preceding_failures)} failed authentication attempts within {duration} seconds "
                            f"(configured threshold: >= {min_failures} failures within {window_sec}s prior to success)."
                        ),
                        host=host,
                        user=ev.user,
                        source_ip=ev.source_ip,
                        first_seen=first_ev.timestamp,
                        last_seen=ev.timestamp,
                        evidence_event_ids=[e.id for e in evidence],
                        mitre_tactic=rule_meta["mitre_tactic"],
                        mitre_technique_id=rule_meta["mitre_technique_id"],
                        mitre_technique_name=rule_meta["mitre_technique_name"],
                        mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                        rule_limitations=rule_meta["limitations"],
                        threshold_snapshot={
                            "suspicious_sequence_failures_before_success": min_failures,
                            "suspicious_sequence_window_seconds": window_sec,
                        },
                    )
                )

    return candidates


def detect_privileged_account_changes(
    events: List[NormalizedEvent], thresholds: DetectionThresholds
) -> List[AlertCandidate]:
    """RULE-PRIV-004: Detect account creation, privileged group additions, or repeated sudo failures."""
    rule_meta = RULE_CATALOG[3]
    monitored_groups_lower = {
        g.lower().strip() for g in thresholds.monitored_privileged_groups
    }
    candidates: List[AlertCandidate] = []

    for ev in events:
        if ev.event_type == EventType.GROUP_MEMBERSHIP_CHANGE:
            target_group = str(ev.details.get("target_group") or "").strip()
            if target_group.lower() in monitored_groups_lower:
                fp = build_alert_fingerprint(
                    rule_meta["rule_id"],
                    ev.host,
                    f"group:{ev.user}:{target_group}",
                    ev.event_hash,
                )
                candidates.append(
                    AlertCandidate(
                        alert_fingerprint=fp,
                        rule_id=rule_meta["rule_id"],
                        rule_name=rule_meta["rule_name"],
                        category=rule_meta["category"],
                        severity=Severity.CRITICAL
                        if target_group.lower()
                        in ("sudo", "wheel", "root", "administrators", "domain admins", "enterprise admins")
                        else Severity.HIGH,
                        title=f"Account '{ev.user}' added to privileged group '{target_group}' on {ev.host}",
                        explanation=(
                            f"User '{ev.user}' was added to security-sensitive group '{target_group}' on host '{host_or_default(ev.host)}' "
                            f"by actor '{ev.actor_user or 'system/root'}'. Target group '{target_group}' is in the monitored privileged groups list."
                        ),
                        host=ev.host,
                        user=ev.user,
                        source_ip=ev.source_ip,
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                        evidence_event_ids=[ev.id],
                        mitre_tactic=rule_meta["mitre_tactic"],
                        mitre_technique_id="T1098",
                        mitre_technique_name="Account Manipulation (Privileged Group Assignment)",
                        mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                        rule_limitations=rule_meta["limitations"],
                        threshold_snapshot={
                            "monitored_privileged_groups": thresholds.monitored_privileged_groups,
                        },
                    )
                )

        elif ev.event_type == EventType.ACCOUNT_CREATED:
            is_uid_zero = bool(ev.details.get("is_uid_zero"))
            fp = build_alert_fingerprint(
                rule_meta["rule_id"],
                ev.host,
                f"new_account:{ev.user}",
                ev.event_hash,
            )
            candidates.append(
                AlertCandidate(
                    alert_fingerprint=fp,
                    rule_id=rule_meta["rule_id"],
                    rule_name=rule_meta["rule_name"],
                    category=rule_meta["category"],
                    severity=Severity.CRITICAL if is_uid_zero else Severity.HIGH,
                    title=f"New account '{ev.user}' created on {ev.host}",
                    explanation=(
                        f"A new user account '{ev.user}' was created on host '{ev.host}' by '{ev.actor_user or 'system'}' "
                        f"via service '{ev.service}'."
                        + (" Warning: Account was assigned UID 0 (root equivalence)." if is_uid_zero else "")
                    ),
                    host=ev.host,
                    user=ev.user,
                    source_ip=ev.source_ip,
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    evidence_event_ids=[ev.id],
                    mitre_tactic=rule_meta["mitre_tactic"],
                    mitre_technique_id="T1136.001",
                    mitre_technique_name="Create Account: Local Account",
                    mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                    rule_limitations=rule_meta["limitations"],
                    threshold_snapshot={
                        "monitored_privileged_groups": thresholds.monitored_privileged_groups,
                    },
                )
            )

    # Also check repeated sudo failures per (host, actor_user)
    sudo_failures_by_actor: Dict[Tuple[str, str], List[NormalizedEvent]] = {}
    for ev in events:
        if ev.event_type == EventType.SUDO_FAILURE:
            actor = ev.actor_user or ev.user or "unknown"
            sudo_failures_by_actor.setdefault((ev.host, actor), []).append(ev)

    for (host, actor), fail_events in sudo_failures_by_actor.items():
        if len(fail_events) >= thresholds.sudo_failure_threshold:
            first_ev = fail_events[0]
            last_ev = fail_events[-1]
            fp = build_alert_fingerprint(
                rule_meta["rule_id"],
                host,
                f"sudo_fail:{actor}",
                first_ev.event_hash,
            )
            commands = sorted({str(e.details.get("command") or "") for e in fail_events if e.details.get("command")})
            candidates.append(
                AlertCandidate(
                    alert_fingerprint=fp,
                    rule_id=rule_meta["rule_id"],
                    rule_name=rule_meta["rule_name"],
                    category=rule_meta["category"],
                    severity=Severity.HIGH,
                    title=f"Unauthorized sudo escalation attempts ({len(fail_events)}) by '{actor}' on {host}",
                    explanation=(
                        f"Account '{actor}' triggered {len(fail_events)} failed sudo elevation attempts on '{host}' "
                        f"(attempted commands: {', '.join(commands) or 'unknown'}). "
                        f"Threshold is >= {thresholds.sudo_failure_threshold} sudo failures."
                    ),
                    host=host,
                    user=actor,
                    source_ip=first_ev.source_ip,
                    first_seen=first_ev.timestamp,
                    last_seen=last_ev.timestamp,
                    evidence_event_ids=[e.id for e in fail_events],
                    mitre_tactic="Privilege Escalation",
                    mitre_technique_id="T1548.003",
                    mitre_technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                    rule_limitations=rule_meta["limitations"],
                    threshold_snapshot={
                        "sudo_failure_threshold": thresholds.sudo_failure_threshold,
                    },
                )
            )

    return candidates


def detect_correlated_compromise_chains(
    events: List[NormalizedEvent],
    seq_candidates: List[AlertCandidate],
    thresholds: DetectionThresholds,
) -> List[AlertCandidate]:
    """RULE-CORR-005: Correlate suspicious login sequences with downstream privilege changes on the same host."""
    rule_meta = RULE_CATALOG[4]
    corr_window = thresholds.correlation_window_seconds
    monitored_groups_lower = {
        g.lower().strip() for g in thresholds.monitored_privileged_groups
    }

    events_by_host: Dict[str, List[NormalizedEvent]] = {}
    for ev in events:
        events_by_host.setdefault(ev.host, []).append(ev)

    candidates: List[AlertCandidate] = []
    for seq in seq_candidates:
        host = seq.host
        seq_end_dt = parse_iso_utc(seq.last_seen)
        host_evs = events_by_host.get(host, [])

        post_auth_priv_events: List[NormalizedEvent] = []
        for ev in host_evs:
            ev_dt = parse_iso_utc(ev.timestamp)
            delta = (ev_dt - seq_end_dt).total_seconds()
            if 0 <= delta <= corr_window:
                if ev.event_type in (
                    EventType.ACCOUNT_CREATED,
                    EventType.SUDO_COMMAND,
                    EventType.SUDO_FAILURE,
                    EventType.PRIVILEGE_ASSIGNED,
                ):
                    post_auth_priv_events.append(ev)
                elif ev.event_type == EventType.GROUP_MEMBERSHIP_CHANGE:
                    grp = str(ev.details.get("target_group") or "").lower().strip()
                    if not grp or grp in monitored_groups_lower:
                        post_auth_priv_events.append(ev)

        if post_auth_priv_events:
            combined_ids: List[int] = list(seq.evidence_event_ids)
            for pev in post_auth_priv_events:
                if pev.id not in combined_ids:
                    combined_ids.append(pev.id)

            last_priv = post_auth_priv_events[-1]
            fp = build_alert_fingerprint(
                rule_meta["rule_id"],
                host,
                f"{seq.user or 'unknown'}:{seq.source_ip or 'local'}",
                seq.alert_fingerprint,
            )
            priv_summary = ", ".join(
                sorted({e.event_type.value for e in post_auth_priv_events})
            )
            candidates.append(
                AlertCandidate(
                    alert_fingerprint=fp,
                    rule_id=rule_meta["rule_id"],
                    rule_name=rule_meta["rule_name"],
                    category=rule_meta["category"],
                    severity=Severity.CRITICAL,
                    title=f"Correlated compromise chain on {host}: suspicious login for '{seq.user}' followed by privilege activity",
                    explanation=(
                        f"Multi-stage attack correlation on '{host}': Account '{seq.user}' logged in from "
                        f"'{seq.source_ip or 'local'}' after repeated authentication failures, and within "
                        f"{int((parse_iso_utc(last_priv.timestamp) - seq_end_dt).total_seconds())} seconds "
                        f"{len(post_auth_priv_events)} privileged/administrative event(s) ({priv_summary}) occurred on the same host "
                        f"(correlation window: {corr_window}s)."
                    ),
                    host=host,
                    user=seq.user,
                    source_ip=seq.source_ip,
                    first_seen=seq.first_seen,
                    last_seen=last_priv.timestamp,
                    evidence_event_ids=combined_ids,
                    mitre_tactic=rule_meta["mitre_tactic"],
                    mitre_technique_id=rule_meta["mitre_technique_id"],
                    mitre_technique_name=rule_meta["mitre_technique_name"],
                    mitre_mapping_rationale=rule_meta["mitre_mapping_rationale"],
                    rule_limitations=rule_meta["limitations"],
                    threshold_snapshot={
                        "suspicious_sequence_failures_before_success": thresholds.suspicious_sequence_failures_before_success,
                        "correlation_window_seconds": corr_window,
                    },
                )
            )

    return candidates


def host_or_default(host: str) -> str:
    return host or "unknown-host"


def get_rule_metadata_list(
    thresholds: DetectionThresholds, alert_counts_by_rule: Dict[str, int]
) -> List[DetectionRuleMetadata]:
    threshold_dict = thresholds.model_dump()
    items: List[DetectionRuleMetadata] = []
    for r in RULE_CATALOG:
        param_names = r["configurable_parameters"]
        current_vals = {k: threshold_dict.get(k) for k in param_names}
        items.append(
            DetectionRuleMetadata(
                rule_id=r["rule_id"],
                rule_name=r["rule_name"],
                category=r["category"],
                default_severity=r["default_severity"],
                description=r["description"],
                mitre_tactic=r["mitre_tactic"],
                mitre_technique_id=r["mitre_technique_id"],
                mitre_technique_name=r["mitre_technique_name"],
                mitre_mapping_rationale=r["mitre_mapping_rationale"],
                limitations=r["limitations"],
                configurable_parameters=param_names,
                current_parameter_values=current_vals,
                alert_count=alert_counts_by_rule.get(r["rule_id"], 0),
            )
        )
    return items
