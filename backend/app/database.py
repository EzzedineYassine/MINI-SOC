from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "mini_soc.db"


def get_db_path() -> str:
    return os.environ.get("MINI_SOC_DB_PATH", str(DEFAULT_DB_PATH))


def init_db(db_path: str | None = None) -> None:
    target_path = db_path or get_db_path()
    conn = sqlite3.connect(target_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                source_format TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user TEXT,
                actor_user TEXT,
                source_ip TEXT,
                service TEXT NOT NULL,
                raw_event TEXT NOT NULL,
                details_json TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 1,
                imported_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_fingerprint TEXT NOT NULL UNIQUE,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                disposition TEXT NOT NULL DEFAULT 'undetermined',
                disposition_reason TEXT,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                host TEXT NOT NULL,
                user TEXT,
                source_ip TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                evidence_count INTEGER NOT NULL DEFAULT 0,
                mitre_tactic TEXT NOT NULL,
                mitre_technique_id TEXT NOT NULL,
                mitre_technique_name TEXT NOT NULL,
                mitre_mapping_rationale TEXT NOT NULL,
                rule_limitations TEXT NOT NULL,
                threshold_snapshot_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                acknowledged_at TEXT,
                acknowledged_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
            CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
            CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);
            CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen);

            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY (alert_id, event_id),
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                action_type TEXT NOT NULL DEFAULT 'note',
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS detection_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                source_format TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 1,
                total_lines INTEGER NOT NULL,
                imported_events INTEGER NOT NULL,
                duplicate_events INTEGER NOT NULL,
                malformed_lines INTEGER NOT NULL,
                new_alerts INTEGER NOT NULL,
                imported_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


@contextmanager
def get_connection(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    target_path = db_path or get_db_path()
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()
