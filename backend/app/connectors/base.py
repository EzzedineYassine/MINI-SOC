from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from ..models import ParseResult, SourceFormat
from ..parsers.linux_auth import parse_linux_auth_log
from ..parsers.validator import detect_source_format, validate_raw_content
from ..parsers.windows_jsonl import parse_windows_jsonl


class LogSourceConnector(ABC):
    """Documented extension interface for connecting external log sources to MINI-SOC.

    IMPORTANT ARCHITECTURAL DISCLOSURE:
    MINI-SOC is an offline-capable educational security monitoring and incident
    investigation lab. No live endpoint agent, kernel telemetry driver, or remote
    network collector is bundled or active by default.

    To integrate a real log source in the future (such as a local rsyslog tailer,
    systemd-journald reader, or Windows Event Forwarding JSONL spooler), implement
    this `LogSourceConnector` interface and pass the resulting `ParseResult` into
    `SecurityRepository.insert_events_idempotent()` followed by
    `DetectionEngine.evaluate_all()`.
    """

    connector_id: str
    display_name: str
    is_live_agent: bool = False

    @abstractmethod
    def fetch_and_parse(self) -> ParseResult:
        """Fetch raw log records from the source and parse into NormalizedEventCreate items."""
        raise NotImplementedError


class LocalBatchFileConnector(LogSourceConnector):
    """Production offline connector that ingests validated local log files (.log, .jsonl)."""

    connector_id = "local_batch_file"
    display_name = "Local File Batch Importer (.log / .jsonl)"
    is_live_agent = False

    def __init__(
        self,
        file_bytes: bytes,
        filename: str,
        source_format: SourceFormat | None = None,
        is_simulated: bool = True,
    ) -> None:
        self.file_bytes = file_bytes
        self.filename = filename
        self.explicit_format = source_format
        self.is_simulated = is_simulated

    def fetch_and_parse(self) -> ParseResult:
        text = validate_raw_content(self.file_bytes)
        fmt = self.explicit_format or detect_source_format(text, self.filename)
        if fmt == SourceFormat.WINDOWS_JSONL:
            return parse_windows_jsonl(text, is_simulated=self.is_simulated)
        return parse_linux_auth_log(text, is_simulated=self.is_simulated)


def get_connector_extension_guide() -> Dict[str, Any]:
    """Return structured documentation describing the active offline ingestion mode
    and the extension point for connecting real log sources in the future."""
    return {
        "environment_mode": "Offline Educational Lab (No Live Endpoint Agent Installed)",
        "live_agent_integrated": False,
        "disclosure": (
            "MINI-SOC operates entirely offline using imported log files and bundled synthetic "
            "datasets. No live endpoint sensor, syslog network daemon, or Windows Event Forwarding "
            "agent is active. All bundled scenarios are clearly marked as simulated data."
        ),
        "extension_interface": "backend/app/connectors/base.py :: LogSourceConnector",
        "active_connectors": [
            {
                "connector_id": LocalBatchFileConnector.connector_id,
                "display_name": LocalBatchFileConnector.display_name,
                "status": "active",
                "mode": "Offline File Upload & Synthetic Lab Packs",
            }
        ],
        "planned_extension_points": [
            {
                "connector_id": "syslog_file_tailer_example",
                "display_name": "Linux /var/log/auth.log Tailer (Extension Point)",
                "status": "extension_template",
                "integration_steps": [
                    "Subclass `LogSourceConnector` in `backend/app/connectors/`.",
                    "Read incremental lines from `/var/log/auth.log` or a syslog relay file.",
                    "Delegate line parsing to `parse_linux_auth_log(chunk, is_simulated=False)`.",
                    "Persist via `SecurityRepository.insert_events_idempotent()` (SHA-256 event_hash prevents duplicates across checkpoint restarts).",
                ],
            },
            {
                "connector_id": "wef_jsonl_spool_example",
                "display_name": "Windows Event Forwarding / Winlogbeat JSONL Spooler (Extension Point)",
                "status": "extension_template",
                "integration_steps": [
                    "Export Windows Security channel events (IDs 4624, 4625, 4672, 4720, 4728, 4732, 4740) to JSONL.",
                    "Subclass `LogSourceConnector` to poll the spool directory or POST to `/api/import/upload`.",
                    "Delegate parsing to `parse_windows_jsonl(chunk, is_simulated=False)`.",
                ],
            },
        ],
    }
