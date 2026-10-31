from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .database import get_connection, init_db
from .models import (
    AlertDetail,
    AlertDisposition,
    AlertStatus,
    AlertSummary,
    AlertUpdateRequest,
    DetectionCategory,
    DetectionThresholds,
    EventType,
    InvestigationNote,
    InvestigationNoteCreate,
    NormalizedEvent,
    NormalizedEventCreate,
    Severity,
    SourceFormat,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SecurityRepository:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path
        init_db(self.db_path)

    def insert_events_idempotent(
        self, events: List[NormalizedEventCreate]
    ) -> Tuple[int, int]:
        """Insert normalized events while deduplicating via event_hash.

        Returns (inserted_count, duplicate_skipped_count).
        """
        inserted = 0
        skipped = 0
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            for ev in events:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        event_hash, timestamp, host, source_format, event_type,
                        user, actor_user, source_ip, service, raw_event,
                        details_json, is_simulated, imported_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev.event_hash,
                        ev.timestamp,
                        ev.host,
                        ev.source_format.value,
                        ev.event_type.value,
                        ev.user,
                        ev.actor_user,
                        ev.source_ip,
                        ev.service,
                        ev.raw_event,
                        json.dumps(ev.details, sort_keys=True),
                        1 if ev.is_simulated else 0,
                        now_iso,
                    ),
                )
                if cursor.rowcount == 1:
                    inserted += 1
                else:
                    skipped += 1
            conn.commit()
        return inserted, skipped

    def _row_to_event(self, row: Any) -> NormalizedEvent:
        return NormalizedEvent(
            id=row["id"],
            event_hash=row["event_hash"],
            timestamp=row["timestamp"],
            host=row["host"],
            source_format=SourceFormat(row["source_format"]),
            event_type=EventType(row["event_type"]),
            user=row["user"],
            actor_user=row["actor_user"],
            source_ip=row["source_ip"],
            service=row["service"],
            raw_event=row["raw_event"],
            details=json.loads(row["details_json"]) if row["details_json"] else {},
            is_simulated=bool(row["is_simulated"]),
            imported_at=row["imported_at"],
        )

    def get_all_events_chronological(self) -> List[NormalizedEvent]:
        with get_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp ASC, id ASC"
            ).fetchall()
            return [self._row_to_event(r) for r in rows]

    def list_events(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 250,
        offset: int = 0,
    ) -> Tuple[List[NormalizedEvent], int]:
        clauses: List[str] = []
        params: List[Any] = []

        if start_time:
            clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(end_time)
        if host:
            clauses.append("LOWER(host) = LOWER(?)")
            params.append(host)
        if user:
            clauses.append("(LOWER(user) = LOWER(?) OR LOWER(actor_user) = LOWER(?))")
            params.extend([user, user])
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if search:
            clauses.append(
                "(LOWER(raw_event) LIKE ? OR LOWER(COALESCE(user, '')) LIKE ? OR LOWER(host) LIKE ? OR LOWER(COALESCE(source_ip, '')) LIKE ?)"
            )
            term = f"%{search.lower()}%"
            params.extend([term, term, term, term])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with get_connection(self.db_path) as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM events {where_sql}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return [self._row_to_event(r) for r in rows], total

    def upsert_alert(
        self,
        alert_fingerprint: str,
        rule_id: str,
        rule_name: str,
        category: DetectionCategory,
        severity: Severity,
        title: str,
        explanation: str,
        host: str,
        user: Optional[str],
        source_ip: Optional[str],
        first_seen: str,
        last_seen: str,
        evidence_event_ids: List[int],
        mitre_tactic: str,
        mitre_technique_id: str,
        mitre_technique_name: str,
        mitre_mapping_rationale: str,
        rule_limitations: str,
        threshold_snapshot: Dict[str, Any],
    ) -> Tuple[int, bool]:
        """Insert a new alert or update evidence links if it already exists.

        Preserves analyst status, disposition, and notes on existing alerts.
        Returns (alert_id, is_newly_created).
        """
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            existing = cursor.execute(
                "SELECT id FROM alerts WHERE alert_fingerprint = ?",
                (alert_fingerprint,),
            ).fetchone()

            if existing:
                alert_id = int(existing["id"])
                is_new = False
                cursor.execute(
                    """
                    UPDATE alerts
                    SET explanation = ?,
                        last_seen = ?,
                        evidence_count = ?,
                        threshold_snapshot_json = ?
                    WHERE id = ?
                    """,
                    (
                        explanation,
                        last_seen,
                        len(evidence_event_ids),
                        json.dumps(threshold_snapshot, sort_keys=True),
                        alert_id,
                    ),
                )
            else:
                is_new = True
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        alert_fingerprint, rule_id, rule_name, category, severity,
                        status, disposition, title, explanation, host, user, source_ip,
                        first_seen, last_seen, evidence_count,
                        mitre_tactic, mitre_technique_id, mitre_technique_name,
                        mitre_mapping_rationale, rule_limitations,
                        threshold_snapshot_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'new', 'undetermined', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_fingerprint,
                        rule_id,
                        rule_name,
                        category.value,
                        severity.value,
                        title,
                        explanation,
                        host,
                        user,
                        source_ip,
                        first_seen,
                        last_seen,
                        len(evidence_event_ids),
                        mitre_tactic,
                        mitre_technique_id,
                        mitre_technique_name,
                        mitre_mapping_rationale,
                        rule_limitations,
                        json.dumps(threshold_snapshot, sort_keys=True),
                        now_iso,
                        now_iso,
                    ),
                )
                alert_id = int(cursor.lastrowid)

            for ev_id in evidence_event_ids:
                cursor.execute(
                    "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?, ?)",
                    (alert_id, ev_id),
                )
            conn.commit()
            return alert_id, is_new

    def prune_stale_uninvestigated_alerts(self, active_fingerprints: List[str]) -> int:
        """When thresholds are tightened and a detection re-scan runs, remove only 'new'
        uninvestigated alerts that no longer match current thresholds. Alerts already
        acknowledged or annotated by an analyst are preserved."""
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            if not active_fingerprints:
                cursor.execute(
                    """
                    DELETE FROM alerts
                    WHERE status = 'new'
                      AND disposition = 'undetermined'
                      AND id NOT IN (SELECT DISTINCT alert_id FROM investigation_notes)
                    """
                )
            else:
                placeholders = ",".join("?" for _ in active_fingerprints)
                cursor.execute(
                    f"""
                    DELETE FROM alerts
                    WHERE status = 'new'
                      AND disposition = 'undetermined'
                      AND id NOT IN (SELECT DISTINCT alert_id FROM investigation_notes)
                      AND alert_fingerprint NOT IN ({placeholders})
                    """,
                    active_fingerprints,
                )
            removed = cursor.rowcount
            conn.commit()
            return removed

    def _row_to_alert_summary(self, row: Any) -> AlertSummary:
        return AlertSummary(
            id=row["id"],
            alert_fingerprint=row["alert_fingerprint"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            category=DetectionCategory(row["category"]),
            severity=Severity(row["severity"]),
            status=AlertStatus(row["status"]),
            disposition=AlertDisposition(row["disposition"]),
            disposition_reason=row["disposition_reason"],
            title=row["title"],
            explanation=row["explanation"],
            host=row["host"],
            user=row["user"],
            source_ip=row["source_ip"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence_count=row["evidence_count"],
            mitre_tactic=row["mitre_tactic"],
            mitre_technique_id=row["mitre_technique_id"],
            mitre_technique_name=row["mitre_technique_name"],
            mitre_mapping_rationale=row["mitre_mapping_rationale"],
            rule_limitations=row["rule_limitations"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
        )

    def list_alerts(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[AlertSummary]:
        clauses: List[str] = []
        params: List[Any] = []

        if start_time:
            clauses.append("last_seen >= ?")
            params.append(start_time)
        if end_time:
            clauses.append("first_seen <= ?")
            params.append(end_time)
        if host:
            clauses.append("LOWER(host) = LOWER(?)")
            params.append(host)
        if user:
            clauses.append("LOWER(user) = LOWER(?)")
            params.append(user)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if search:
            clauses.append(
                "(LOWER(title) LIKE ? OR LOWER(explanation) LIKE ? OR LOWER(host) LIKE ? OR LOWER(COALESCE(user, '')) LIKE ? OR LOWER(mitre_technique_id) LIKE ?)"
            )
            term = f"%{search.lower()}%"
            params.extend([term, term, term, term, term])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        severity_order = """
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        """
        with get_connection(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where_sql} ORDER BY {severity_order} ASC, first_seen DESC, id DESC",
                params,
            ).fetchall()
            return [self._row_to_alert_summary(r) for r in rows]

    def get_alert_detail(self, alert_id: int) -> Optional[AlertDetail]:
        with get_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if not row:
                return None

            ev_rows = conn.execute(
                """
                SELECT e.*
                FROM events e
                INNER JOIN alert_evidence ae ON ae.event_id = e.id
                WHERE ae.alert_id = ?
                ORDER BY e.timestamp ASC, e.id ASC
                """,
                (alert_id,),
            ).fetchall()

            note_rows = conn.execute(
                """
                SELECT * FROM investigation_notes
                WHERE alert_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (alert_id,),
            ).fetchall()

            summary = self._row_to_alert_summary(row)
            return AlertDetail(
                **summary.model_dump(),
                evidence_events=[self._row_to_event(er) for er in ev_rows],
                notes=[
                    InvestigationNote(
                        id=nr["id"],
                        alert_id=nr["alert_id"],
                        author=nr["author"],
                        note=nr["note"],
                        action_type=nr["action_type"],
                        created_at=nr["created_at"],
                    )
                    for nr in note_rows
                ],
                threshold_snapshot=json.loads(row["threshold_snapshot_json"])
                if row["threshold_snapshot_json"]
                else {},
            )

    def update_alert_investigation(
        self, alert_id: int, req: AlertUpdateRequest
    ) -> Optional[AlertDetail]:
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if not row:
                return None

            current_status = row["status"]
            current_disposition = row["disposition"]
            current_reason = row["disposition_reason"]
            acknowledged_at = row["acknowledged_at"]
            acknowledged_by = row["acknowledged_by"]

            new_status = req.status.value if req.status else current_status
            new_disposition = (
                req.disposition.value if req.disposition else current_disposition
            )
            new_reason = (
                req.disposition_reason
                if req.disposition_reason is not None
                else current_reason
            )

            audit_changes: List[str] = []
            if new_status != current_status:
                audit_changes.append(f"Status changed from '{current_status}' to '{new_status}'")
                if new_status in ("acknowledged", "in_progress", "resolved") and not acknowledged_at:
                    acknowledged_at = now_iso
                    acknowledged_by = req.analyst

            if new_disposition != current_disposition:
                audit_changes.append(
                    f"Disposition changed from '{current_disposition}' to '{new_disposition}'"
                )

            if req.disposition_reason is not None and req.disposition_reason != current_reason:
                audit_changes.append(f"Disposition rationale updated: {req.disposition_reason}")

            conn.execute(
                """
                UPDATE alerts
                SET status = ?,
                    disposition = ?,
                    disposition_reason = ?,
                    acknowledged_at = ?,
                    acknowledged_by = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    new_status,
                    new_disposition,
                    new_reason,
                    acknowledged_at,
                    acknowledged_by,
                    now_iso,
                    alert_id,
                ),
            )

            if audit_changes:
                conn.execute(
                    """
                    INSERT INTO investigation_notes (alert_id, author, note, action_type, created_at)
                    VALUES (?, ?, ?, 'status_change', ?)
                    """,
                    (alert_id, req.analyst, " | ".join(audit_changes), now_iso),
                )

            if req.note and req.note.strip():
                conn.execute(
                    """
                    INSERT INTO investigation_notes (alert_id, author, note, action_type, created_at)
                    VALUES (?, ?, ?, 'note', ?)
                    """,
                    (alert_id, req.analyst, req.note.strip(), now_iso),
                )

            conn.commit()
        return self.get_alert_detail(alert_id)

    def add_investigation_note(
        self, alert_id: int, req: InvestigationNoteCreate
    ) -> Optional[AlertDetail]:
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if not row:
                return None

            conn.execute(
                """
                INSERT INTO investigation_notes (alert_id, author, note, action_type, created_at)
                VALUES (?, ?, ?, 'note', ?)
                """,
                (alert_id, req.author.strip(), req.note.strip(), now_iso),
            )
            conn.execute(
                "UPDATE alerts SET updated_at = ? WHERE id = ?",
                (now_iso, alert_id),
            )
            conn.commit()
        return self.get_alert_detail(alert_id)

    def get_thresholds(self) -> DetectionThresholds:
        with get_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT config_json FROM detection_config WHERE id = 1"
            ).fetchone()
            if not row:
                defaults = DetectionThresholds()
                self.save_thresholds(defaults)
                return defaults
            data = json.loads(row["config_json"])
            return DetectionThresholds(**data)

    def save_thresholds(self, thresholds: DetectionThresholds) -> DetectionThresholds:
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO detection_config (id, config_json, updated_at)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    config_json = excluded.config_json,
                    updated_at = excluded.updated_at
                """,
                (json.dumps(thresholds.model_dump(), sort_keys=True), now_iso),
            )
            conn.commit()
        return thresholds

    def record_import_history(
        self,
        source_name: str,
        source_format: SourceFormat,
        is_simulated: bool,
        total_lines: int,
        imported_events: int,
        duplicate_events: int,
        malformed_lines: int,
        new_alerts: int,
    ) -> None:
        now_iso = utc_now_iso()
        with get_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO import_history (
                    source_name, source_format, is_simulated, total_lines,
                    imported_events, duplicate_events, malformed_lines,
                    new_alerts, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_name,
                    source_format.value,
                    1 if is_simulated else 0,
                    total_lines,
                    imported_events,
                    duplicate_events,
                    malformed_lines,
                    new_alerts,
                    now_iso,
                ),
            )
            conn.commit()

    def get_dashboard_summary(self) -> Dict[str, Any]:
        with get_connection(self.db_path) as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
            ):
                severity_counts[row["severity"]] = row["cnt"]

            status_counts = {
                "new": 0,
                "acknowledged": 0,
                "in_progress": 0,
                "resolved": 0,
                "false_positive": 0,
            }
            for row in conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM alerts GROUP BY status"
            ):
                status_counts[row["status"]] = row["cnt"]

            category_counts: Dict[str, int] = {}
            for row in conn.execute(
                "SELECT category, COUNT(*) AS cnt FROM alerts GROUP BY category"
            ):
                category_counts[row["category"]] = row["cnt"]

            event_type_counts: Dict[str, int] = {}
            for row in conn.execute(
                "SELECT event_type, COUNT(*) AS cnt FROM events GROUP BY event_type"
            ):
                event_type_counts[row["event_type"]] = row["cnt"]

            hosts = [
                r["host"]
                for r in conn.execute(
                    "SELECT DISTINCT host FROM events ORDER BY host ASC"
                ).fetchall()
            ]
            users = [
                r["user"]
                for r in conn.execute(
                    "SELECT DISTINCT user FROM events WHERE user IS NOT NULL ORDER BY user ASC"
                ).fetchall()
            ]

            # Build timeline grouped by 5-minute buckets (YYYY-MM-DDTHH:MM)
            timeline_rows = conn.execute(
                """
                SELECT
                    SUBSTR(timestamp, 1, 15) || '0:00Z' AS bucket,
                    COUNT(*) AS total,
                    SUM(CASE WHEN event_type IN ('auth_failure', 'sudo_failure') THEN 1 ELSE 0 END) AS failures,
                    SUM(CASE WHEN event_type = 'auth_success' THEN 1 ELSE 0 END) AS successes,
                    SUM(CASE WHEN event_type IN ('account_created', 'group_membership_change', 'privilege_assigned', 'sudo_command') THEN 1 ELSE 0 END) AS privileged_events
                FROM events
                GROUP BY bucket
                ORDER BY bucket ASC
                """
            ).fetchall()

            timeline = [
                {
                    "bucket": r["bucket"],
                    "total": r["total"],
                    "failures": r["failures"],
                    "successes": r["successes"],
                    "privileged_events": r["privileged_events"],
                }
                for r in timeline_rows
            ]

            imports = [
                {
                    "id": r["id"],
                    "source_name": r["source_name"],
                    "source_format": r["source_format"],
                    "is_simulated": bool(r["is_simulated"]),
                    "total_lines": r["total_lines"],
                    "imported_events": r["imported_events"],
                    "duplicate_events": r["duplicate_events"],
                    "malformed_lines": r["malformed_lines"],
                    "new_alerts": r["new_alerts"],
                    "imported_at": r["imported_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM import_history ORDER BY id DESC LIMIT 15"
                ).fetchall()
            ]

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "severity_counts": severity_counts,
                "status_counts": status_counts,
                "category_counts": category_counts,
                "event_type_counts": event_type_counts,
                "hosts": hosts,
                "users": users,
                "timeline": timeline,
                "import_history": imports,
            }

    def reset_workspace(self) -> None:
        with get_connection(self.db_path) as conn:
            conn.executescript(
                """
                DELETE FROM alert_evidence;
                DELETE FROM investigation_notes;
                DELETE FROM alerts;
                DELETE FROM events;
                DELETE FROM import_history;
                """
            )
            conn.commit()
