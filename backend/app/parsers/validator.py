from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

from ..models import EventType, SourceFormat

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB cap to prevent resource exhaustion
MAX_LINES_PER_IMPORT = 10_000
DEFAULT_SYSLOG_YEAR = 2026

SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_TS_RE = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})$"
)


class LogValidationError(ValueError):
    """Raised when an uploaded log file violates size or structural constraints."""


def validate_raw_content(content_bytes: bytes) -> str:
    if not content_bytes:
        raise LogValidationError("Uploaded log content is empty.")
    if len(content_bytes) > MAX_UPLOAD_BYTES:
        raise LogValidationError(
            f"Log file exceeds maximum allowed size of {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )
    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LogValidationError(
            "Log file must be valid UTF-8 encoded plain text or JSONL."
        ) from exc

    lines = text.splitlines()
    if len(lines) > MAX_LINES_PER_IMPORT:
        raise LogValidationError(
            f"Log file contains {len(lines)} lines, exceeding the limit of {MAX_LINES_PER_IMPORT} lines per import."
        )
    return text


def normalize_timestamp(
    raw_ts: str, default_year: int = DEFAULT_SYSLOG_YEAR
) -> str:
    """Normalize diverse timestamp strings into canonical ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ)."""
    cleaned = raw_ts.strip()
    if not cleaned:
        raise ValueError("Empty timestamp string")

    m_syslog = SYSLOG_TS_RE.match(cleaned)
    if m_syslog:
        month = SYSLOG_MONTHS[m_syslog.group("month")]
        day = int(m_syslog.group("day"))
        hour = int(m_syslog.group("hour"))
        minute = int(m_syslog.group("minute"))
        second = int(m_syslog.group("second"))
        dt = datetime(default_year, month, day, hour, minute, second, tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    iso_candidate = cleaned
    if iso_candidate.endswith("Z") or iso_candidate.endswith("z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"Unrecognized or invalid timestamp '{raw_ts}'") from exc


def compute_event_hash(
    timestamp: str,
    host: str,
    source_format: SourceFormat,
    event_type: EventType,
    user: Optional[str],
    actor_user: Optional[str],
    source_ip: Optional[str],
    service: str,
    raw_event: str,
) -> str:
    """Compute a deterministic SHA-256 hash so re-importing the same log line is idempotent."""
    canonical = "|".join(
        [
            timestamp,
            host.lower().strip(),
            source_format.value,
            event_type.value,
            (user or "").strip(),
            (actor_user or "").strip(),
            (source_ip or "").strip(),
            service.strip(),
            raw_event.strip(),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def detect_source_format(text: str, filename: Optional[str] = None) -> SourceFormat:
    if filename:
        lower_name = filename.lower()
        if lower_name.endswith(".jsonl") or lower_name.endswith(".json"):
            return SourceFormat.WINDOWS_JSONL
        if lower_name.endswith(".log"):
            return SourceFormat.LINUX_AUTH

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{") and line.endswith("}"):
            return SourceFormat.WINDOWS_JSONL
        return SourceFormat.LINUX_AUTH

    return SourceFormat.LINUX_AUTH
