from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

from ..models import (
    EventType,
    NormalizedEventCreate,
    ParseErrorDetail,
    ParseResult,
    SourceFormat,
)
from .validator import DEFAULT_SYSLOG_YEAR, compute_event_hash, normalize_timestamp

HEADER_SYSLOG_RE = re.compile(
    r"^(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[A-Za-z0-9._-]+)\s+"
    r"(?P<service>[A-Za-z0-9._/-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

HEADER_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?P<host>[A-Za-z0-9._-]+)\s+"
    r"(?P<service>[A-Za-z0-9._/-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

SSHD_FAILED_RE = re.compile(
    r"^Failed\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>[A-Za-z0-9._$-]+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)(?:\s+ssh2)?(?:\s*:\s*(?P<extra>.*))?$"
)

SSHD_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?P<user>[A-Za-z0-9._$-]+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)(?:\s+ssh2)?(?:\s*:\s*(?P<extra>.*))?$"
)

SSHD_INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(?P<user>[A-Za-z0-9._$-]+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)(?:\s+port\s+(?P<port>\d+))?"
)

SUDO_FAIL_RE = re.compile(
    r"^(?P<actor>[A-Za-z0-9._$-]+)\s*:\s*"
    r"(?P<reason>(?:\d+\s+incorrect password attempts?|user NOT in sudoers|authentication failure))\s*;\s*"
    r"TTY=(?P<tty>[^;]+?)\s*;\s*PWD=(?P<pwd>[^;]+?)\s*;\s*USER=(?P<target>[A-Za-z0-9._$-]+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)

SUDO_CMD_RE = re.compile(
    r"^(?P<actor>[A-Za-z0-9._$-]+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+?)\s*;\s*PWD=(?P<pwd>[^;]+?)\s*;\s*USER=(?P<target>[A-Za-z0-9._$-]+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)

USERADD_RE = re.compile(
    r"^new user:\s*name=(?P<user>[A-Za-z0-9._$-]+),\s*UID=(?P<uid>\d+),\s*GID=(?P<gid>\d+),\s*home=(?P<home>[^,]+),\s*shell=(?P<shell>[^\s,]+)"
)

USERMOD_GROUP_RE = re.compile(
    r"^add\s+'(?P<user>[A-Za-z0-9._$-]+)'\s+to\s+(?:shadow\s+)?group\s+'(?P<group>[A-Za-z0-9._$-]+)'$"
)

GPASSWD_GROUP_RE = re.compile(
    r"^added user\s+(?P<user>[A-Za-z0-9._$-]+)\s+to group\s+(?P<group>[A-Za-z0-9._$-]+)(?:\s+by\s+(?P<actor>[A-Za-z0-9._$-]+))?$"
)

SU_FAIL_RE = re.compile(
    r"^FAILED SU \(to (?P<target>[A-Za-z0-9._$-]+)\) (?P<actor>[A-Za-z0-9._$-]+) on (?P<tty>\S+)$"
)

SU_SUCCESS_RE = re.compile(
    r"^session opened for user (?P<target>[A-Za-z0-9._$-]+) by (?P<actor>[A-Za-z0-9._$-]*)\(uid=\d+\)$"
)


def _classify_linux_message(
    service: str, message: str
) -> Optional[Tuple[EventType, Optional[str], Optional[str], Optional[str], Dict[str, Any]]]:
    msg = message.strip()

    m = SSHD_FAILED_RE.match(msg)
    if m:
        user = m.group("user")
        ip = m.group("ip")
        invalid_user = bool(m.group("invalid"))
        return (
            EventType.AUTH_FAILURE,
            user,
            None,
            ip,
            {
                "auth_method": m.group("method"),
                "invalid_user": invalid_user,
                "port": int(m.group("port")),
                "failure_reason": "invalid_user" if invalid_user else "bad_credentials",
            },
        )

    m = SSHD_ACCEPTED_RE.match(msg)
    if m:
        user = m.group("user")
        ip = m.group("ip")
        return (
            EventType.AUTH_SUCCESS,
            user,
            user,
            ip,
            {
                "auth_method": m.group("method"),
                "port": int(m.group("port")),
                "signature": (m.group("extra") or "").strip() or None,
            },
        )

    m = SSHD_INVALID_USER_RE.match(msg)
    if m:
        user = m.group("user")
        ip = m.group("ip")
        port_str = m.group("port")
        return (
            EventType.AUTH_FAILURE,
            user,
            None,
            ip,
            {
                "auth_method": "ssh_preauth",
                "invalid_user": True,
                "port": int(port_str) if port_str else None,
                "failure_reason": "invalid_user_probe",
            },
        )

    m = SUDO_FAIL_RE.match(msg)
    if m:
        actor = m.group("actor")
        target = m.group("target")
        return (
            EventType.SUDO_FAILURE,
            target,
            actor,
            None,
            {
                "reason": m.group("reason").strip(),
                "tty": m.group("tty").strip(),
                "pwd": m.group("pwd").strip(),
                "target_user": target,
                "command": m.group("cmd").strip(),
            },
        )

    m = SUDO_CMD_RE.match(msg)
    if m:
        actor = m.group("actor")
        target = m.group("target")
        return (
            EventType.SUDO_COMMAND,
            target,
            actor,
            None,
            {
                "tty": m.group("tty").strip(),
                "pwd": m.group("pwd").strip(),
                "target_user": target,
                "command": m.group("cmd").strip(),
            },
        )

    m = USERADD_RE.match(msg)
    if m:
        user = m.group("user")
        uid = int(m.group("uid"))
        gid = int(m.group("gid"))
        return (
            EventType.ACCOUNT_CREATED,
            user,
            "root",
            None,
            {
                "uid": uid,
                "gid": gid,
                "home": m.group("home"),
                "shell": m.group("shell"),
                "is_uid_zero": uid == 0,
            },
        )

    m = USERMOD_GROUP_RE.match(msg)
    if m:
        user = m.group("user")
        group = m.group("group")
        return (
            EventType.GROUP_MEMBERSHIP_CHANGE,
            user,
            "root",
            None,
            {
                "target_group": group,
                "action": "group_add",
                "mechanism": service,
            },
        )

    m = GPASSWD_GROUP_RE.match(msg)
    if m:
        user = m.group("user")
        group = m.group("group")
        actor = m.group("actor") or "root"
        return (
            EventType.GROUP_MEMBERSHIP_CHANGE,
            user,
            actor,
            None,
            {
                "target_group": group,
                "action": "group_add",
                "mechanism": service,
            },
        )

    m = SU_FAIL_RE.match(msg)
    if m:
        return (
            EventType.AUTH_FAILURE,
            m.group("target"),
            m.group("actor"),
            None,
            {
                "auth_method": "su",
                "tty": m.group("tty"),
                "failure_reason": "su_auth_failed",
            },
        )

    m = SU_SUCCESS_RE.match(msg)
    if m:
        return (
            EventType.PRIVILEGE_ASSIGNED,
            m.group("target"),
            m.group("actor") or "root",
            None,
            {
                "mechanism": "pam_unix_su",
                "action": "session_opened",
            },
        )

    return None


def parse_linux_auth_log(
    text: str,
    is_simulated: bool = True,
    default_year: int = DEFAULT_SYSLOG_YEAR,
) -> ParseResult:
    """Parse Linux auth.log / syslog lines into NormalizedEventCreate objects."""
    result = ParseResult()
    for idx, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        result.total_lines_processed += 1
        header_match = HEADER_ISO_RE.match(stripped) or HEADER_SYSLOG_RE.match(stripped)
        if not header_match:
            result.errors.append(
                ParseErrorDetail(
                    line_number=idx,
                    raw_excerpt=stripped[:160],
                    reason="Malformed syslog header (expected '<timestamp> <host> <service>[pid]: <message>')",
                )
            )
            continue

        raw_ts = header_match.group("ts")
        host = header_match.group("host")
        service = header_match.group("service")
        pid = header_match.group("pid")
        message = header_match.group("message")

        try:
            iso_ts = normalize_timestamp(raw_ts, default_year=default_year)
        except ValueError as exc:
            result.errors.append(
                ParseErrorDetail(
                    line_number=idx,
                    raw_excerpt=stripped[:160],
                    reason=str(exc),
                )
            )
            continue

        classified = _classify_linux_message(service, message)
        if not classified:
            result.errors.append(
                ParseErrorDetail(
                    line_number=idx,
                    raw_excerpt=stripped[:160],
                    reason=f"Unsupported or unrecognized Linux auth message pattern for service '{service}'",
                )
            )
            continue

        event_type, user, actor_user, source_ip, details = classified
        if pid:
            details["pid"] = int(pid)

        event_hash = compute_event_hash(
            timestamp=iso_ts,
            host=host,
            source_format=SourceFormat.LINUX_AUTH,
            event_type=event_type,
            user=user,
            actor_user=actor_user,
            source_ip=source_ip,
            service=service,
            raw_event=stripped,
        )

        result.events.append(
            NormalizedEventCreate(
                event_hash=event_hash,
                timestamp=iso_ts,
                host=host,
                source_format=SourceFormat.LINUX_AUTH,
                event_type=event_type,
                user=user,
                actor_user=actor_user,
                source_ip=source_ip,
                service=service,
                raw_event=stripped,
                details=details,
                is_simulated=is_simulated,
            )
        )

    return result
