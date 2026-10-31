from __future__ import annotations

import json
from typing import Any, Dict, Optional

from ..models import (
    EventType,
    NormalizedEventCreate,
    ParseErrorDetail,
    ParseResult,
    SourceFormat,
)
from .validator import compute_event_hash, normalize_timestamp

SUPPORTED_WINDOWS_EVENT_IDS = {
    4624: EventType.AUTH_SUCCESS,
    4625: EventType.AUTH_FAILURE,
    4672: EventType.PRIVILEGE_ASSIGNED,
    4720: EventType.ACCOUNT_CREATED,
    4728: EventType.GROUP_MEMBERSHIP_CHANGE,
    4732: EventType.GROUP_MEMBERSHIP_CHANGE,
    4756: EventType.GROUP_MEMBERSHIP_CHANGE,
    4740: EventType.ACCOUNT_LOCKED,
}


def _first_non_empty(data: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in data and data[k] not in (None, "", "-"):
            return data[k]
    return None


def parse_windows_jsonl(text: str, is_simulated: bool = True) -> ParseResult:
    """Parse structured Windows Security Event JSONL records into NormalizedEventCreate objects."""
    result = ParseResult()

    for idx, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip().replace("\x00", "")
        if not stripped or stripped.startswith("#"):
            continue

        result.total_lines_processed += 1
        try:
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason=f"Invalid JSON syntax: {exc.msg}",
                    )
                )
                continue

            if not isinstance(payload, dict):
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason="JSONL record must be a JSON object",
                    )
                )
                continue

            system_block = payload.get("System") if isinstance(payload.get("System"), dict) else {}
            event_data = payload.get("EventData") if isinstance(payload.get("EventData"), dict) else {}
            merged: Dict[str, Any] = {**system_block, **event_data, **payload}

            raw_ts = _first_non_empty(
                merged, "timestamp", "TimeCreated", "@timestamp", "UtcTime", "EventTime"
            )
            if isinstance(raw_ts, dict):
                raw_ts = raw_ts.get("SystemTime") or raw_ts.get("#text")

            host = _first_non_empty(merged, "host", "Computer", "Hostname", "WorkstationName")
            raw_event_id = _first_non_empty(merged, "event_id", "EventID", "Id")

            if not raw_ts or not host or raw_event_id is None:
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason="Missing required Windows event field(s): timestamp/TimeCreated, host/Computer, or event_id/EventID",
                    )
                )
                continue

            try:
                event_id = int(raw_event_id)
            except (TypeError, ValueError):
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason=f"Invalid non-integer Windows EventID '{raw_event_id}'",
                    )
                )
                continue

            if event_id not in SUPPORTED_WINDOWS_EVENT_IDS:
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason=f"Unsupported Windows EventID {event_id} (supported: {sorted(SUPPORTED_WINDOWS_EVENT_IDS.keys())})",
                    )
                )
                continue

            try:
                iso_ts = normalize_timestamp(str(raw_ts))
            except ValueError as exc:
                result.errors.append(
                    ParseErrorDetail(
                        line_number=idx,
                        raw_excerpt=stripped[:160],
                        reason=str(exc),
                    )
                )
                continue

            event_type = SUPPORTED_WINDOWS_EVENT_IDS[event_id]
            target_user = _first_non_empty(
                merged, "user", "target_user", "TargetUserName", "MemberName"
            )
            subject_user = _first_non_empty(
                merged, "actor_user", "subject_user", "SubjectUserName"
            )
            if event_id == 4672 and not target_user and subject_user:
                target_user = subject_user

            source_ip = _first_non_empty(
                merged, "source_ip", "IpAddress", "ClientAddress", "SourceNetworkAddress"
            )
            if source_ip in ("::1", "127.0.0.1", "-"):
                source_ip = str(source_ip) if source_ip != "-" else None

            service = str(
                _first_non_empty(
                    merged,
                    "service",
                    "Provider",
                    "Channel",
                )
                or "Microsoft-Windows-Security-Auditing"
            )

            details: Dict[str, Any] = {"event_id": event_id}
            logon_type = _first_non_empty(merged, "logon_type", "LogonType")
            if logon_type is not None:
                try:
                    details["logon_type"] = int(logon_type)
                except (TypeError, ValueError):
                    details["logon_type"] = str(logon_type)

            group_name = _first_non_empty(
                merged, "target_group", "group_name", "GroupName", "TargetGroupName"
            )
            if group_name:
                details["target_group"] = str(group_name)

            privs = _first_non_empty(merged, "privileges", "PrivilegeList")
            if privs:
                if isinstance(privs, list):
                    details["privileges"] = [str(p) for p in privs]
                else:
                    details["privileges"] = [
                        p.strip() for p in str(privs).replace("\n", " ").split() if p.strip()
                    ]

            status_code = _first_non_empty(merged, "status", "Status", "SubStatus")
            if status_code:
                details["status_code"] = str(status_code)

            failure_reason = _first_non_empty(merged, "failure_reason", "FailureReason")
            if failure_reason:
                details["failure_reason"] = str(failure_reason)

            auth_pkg = _first_non_empty(
                merged, "auth_package", "AuthenticationPackageName", "LogonProcessName"
            )
            if auth_pkg:
                details["auth_package"] = str(auth_pkg)

            workstation = _first_non_empty(
                merged, "workstation", "WorkstationName", "CallerComputerName"
            )
            if workstation:
                details["workstation"] = str(workstation)

            canonical_raw = json.dumps(payload, sort_keys=True)
            event_hash = compute_event_hash(
                timestamp=iso_ts,
                host=str(host),
                source_format=SourceFormat.WINDOWS_JSONL,
                event_type=event_type,
                user=str(target_user) if target_user is not None else None,
                actor_user=str(subject_user) if subject_user is not None else None,
                source_ip=str(source_ip) if source_ip is not None else None,
                service=service,
                raw_event=canonical_raw,
            )

            result.events.append(
                NormalizedEventCreate(
                    event_hash=event_hash,
                    timestamp=iso_ts,
                    host=str(host),
                    source_format=SourceFormat.WINDOWS_JSONL,
                    event_type=event_type,
                    user=str(target_user) if target_user is not None else None,
                    actor_user=str(subject_user) if subject_user is not None else None,
                    source_ip=str(source_ip) if source_ip is not None else None,
                    service=service,
                    raw_event=stripped,
                    details=details,
                    is_simulated=is_simulated,
                )
            )
        except Exception as exc:
            result.errors.append(
                ParseErrorDetail(
                    line_number=idx,
                    raw_excerpt=stripped[:160],
                    reason=f"Unhandled parsing error: {exc}",
                )
            )

    return result
