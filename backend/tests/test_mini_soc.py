from __future__ import annotations

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.detections.rules import (
    detect_brute_force,
    detect_password_spraying,
    detect_privileged_account_changes,
    detect_suspicious_auth_sequences,
)
from app.main import app
from app.models import DetectionThresholds, SourceFormat
from app.parsers.linux_auth import parse_linux_auth_log
from app.parsers.validator import (
    MAX_LINES_PER_IMPORT,
    MAX_UPLOAD_BYTES,
    LogValidationError,
    normalize_timestamp,
    validate_raw_content,
)
from app.parsers.windows_jsonl import parse_windows_jsonl
from app.repository import SecurityRepository


@pytest.fixture()
def temp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    db_file = tmp_path / "test_mini_soc.db"
    monkeypatch.setenv("MINI_SOC_DB_PATH", str(db_file))
    init_db(str(db_file))
    return str(db_file)


@pytest.fixture()
def client(temp_db: str) -> TestClient:
    return TestClient(app)


def test_timestamp_normalization_formats() -> None:
    # Traditional syslog RFC 3164
    assert normalize_timestamp("Oct 30 08:15:02", default_year=2026) == "2026-10-30T08:15:02Z"
    # ISO-8601 UTC
    assert normalize_timestamp("2026-10-30T08:15:02Z") == "2026-10-30T08:15:02Z"
    # ISO-8601 with positive timezone offset (+02:00 -> 06:15:02Z)
    assert normalize_timestamp("2026-10-30T08:15:02+02:00") == "2026-10-30T06:15:02Z"
    # Fractional seconds
    assert normalize_timestamp("2026-10-30 14:22:19.481Z") == "2026-10-30T14:22:19Z"

    with pytest.raises(ValueError):
        normalize_timestamp("not-a-timestamp")


def test_file_resource_limits_and_validation() -> None:
    with pytest.raises(LogValidationError, match="empty"):
        validate_raw_content(b"")

    oversized = b"a" * (MAX_UPLOAD_BYTES + 10)
    with pytest.raises(LogValidationError, match="maximum allowed size"):
        validate_raw_content(oversized)

    too_many_lines = ("\n".join(["line"] * (MAX_LINES_PER_IMPORT + 5))).encode("utf-8")
    with pytest.raises(LogValidationError, match="exceeding the limit"):
        validate_raw_content(too_many_lines)


def test_linux_parser_valid_and_malformed_lines() -> None:
    raw_log = "\n".join(
        [
            "# Comment line should be ignored",
            "Oct 30 09:00:01 web-01 sshd[101]: Failed password for invalid user root from 192.0.2.10 port 50001 ssh2",
            "2026-10-30T09:00:05+00:00 web-01 sshd[102]: Accepted password for deploy from 192.0.2.10 port 50002 ssh2",
            "THIS_IS_A_MALFORMED_LINE_WITHOUT_HEADER",
            "2026-10-30T09:01:00Z web-01 kernel[1]: Unrecognized kernel message that is not auth",
            "2026-10-30T09:02:00Z web-01 usermod[109]: add 'deploy' to group 'sudo'",
        ]
    )
    res = parse_linux_auth_log(raw_log)
    assert res.total_lines_processed == 5
    assert len(res.events) == 3
    assert len(res.errors) == 2
    assert res.errors[0].line_number == 4
    assert res.errors[1].line_number == 5
    assert res.events[0].event_type.value == "auth_failure"
    assert res.events[1].event_type.value == "auth_success"
    assert res.events[2].event_type.value == "group_membership_change"
    assert res.events[2].details["target_group"] == "sudo"


def test_windows_jsonl_parser_valid_and_malformed_lines() -> None:
    raw_jsonl = "\n".join(
        [
            '{"TimeCreated":"2026-10-30T10:00:01Z","Computer":"WIN-01","EventID":4625,"TargetUserName":"alice","IpAddress":"10.0.0.5"}',
            '{"broken_json": ',
            '[1, 2, 3]',
            '{"TimeCreated":"2026-10-30T10:00:02Z","Computer":"WIN-01"}',
            '{"TimeCreated":"2026-10-30T10:00:03Z","Computer":"WIN-01","EventID":9999}',
            '{"System":{"TimeCreated":"2026-10-30T10:01:00Z","Computer":"WIN-01","EventID":4732},"EventData":{"MemberName":"alice","GroupName":"Administrators","SubjectUserName":"admin"}}',
        ]
    )
    res = parse_windows_jsonl(raw_jsonl)
    assert res.total_lines_processed == 6
    assert len(res.events) == 2
    assert len(res.errors) == 4
    assert res.events[0].event_type.value == "auth_failure"
    assert res.events[0].user == "alice"
    assert res.events[1].event_type.value == "group_membership_change"
    assert res.events[1].details["target_group"] == "Administrators"


def test_threshold_boundary_conditions_for_brute_force_and_sequence(temp_db: str) -> None:
    repo = SecurityRepository(temp_db)
    thresholds = DetectionThresholds(
        brute_force_failure_threshold=4,
        brute_force_window_seconds=60,
        suspicious_sequence_failures_before_success=3,
        suspicious_sequence_window_seconds=120,
    )

    # Case 1: Only 3 failures (N - 1 = 3 < 4) within 60s -> 0 brute force alerts
    lines_below = "\n".join(
        [
            "2026-10-30T12:00:00Z host-a sshd[1]: Failed password for bob from 198.51.100.9 port 4001 ssh2",
            "2026-10-30T12:00:20Z host-a sshd[2]: Failed password for bob from 198.51.100.9 port 4002 ssh2",
            "2026-10-30T12:00:40Z host-a sshd[3]: Failed password for bob from 198.51.100.9 port 4003 ssh2",
        ]
    )
    parsed_below = parse_linux_auth_log(lines_below)
    repo.insert_events_idempotent(parsed_below.events)
    stored = repo.get_all_events_chronological()
    assert len(detect_brute_force(stored, thresholds)) == 0

    # Case 2: 4th failure at 12:01:01Z (61 seconds after first failure -> outside 60s window from first)
    line_outside_window = "2026-10-30T12:01:01Z host-a sshd[4]: Failed password for bob from 198.51.100.9 port 4004 ssh2"
    repo.insert_events_idempotent(parse_linux_auth_log(line_outside_window).events)
    stored = repo.get_all_events_chronological()
    assert len(detect_brute_force(stored, thresholds)) == 0

    # Case 3: 5th failure at 12:01:20Z -> now failures [2,3,4,5] span 12:00:20Z..12:01:20Z (exact 60s boundary!) -> 1 alert
    line_exact_boundary = "2026-10-30T12:01:20Z host-a sshd[5]: Failed password for bob from 198.51.100.9 port 4005 ssh2"
    repo.insert_events_idempotent(parse_linux_auth_log(line_exact_boundary).events)
    stored = repo.get_all_events_chronological()
    bf_alerts = detect_brute_force(stored, thresholds)
    assert len(bf_alerts) == 1
    assert bf_alerts[0].evidence_event_ids == [2, 3, 4, 5]

    # Case 4: Successful login at 12:01:30Z -> preceded by failures within 120s -> triggers suspicious sequence
    line_success = "2026-10-30T12:01:30Z host-a sshd[6]: Accepted password for bob from 198.51.100.9 port 4006 ssh2"
    repo.insert_events_idempotent(parse_linux_auth_log(line_success).events)
    stored = repo.get_all_events_chronological()
    seq_alerts = detect_suspicious_auth_sequences(stored, thresholds)
    assert len(seq_alerts) == 1
    assert seq_alerts[0].mitre_technique_id == "T1078"


def test_end_to_end_sample_import_deduplication_and_investigation_workflow(
    client: TestClient,
) -> None:
    # 1. Import all supplied example logs
    res = client.post("/api/import/sample/all")
    assert res.status_code == 200
    import_reports = res.json()
    assert len(import_reports) == 2

    linux_report = import_reports[0]
    windows_report = import_reports[1]
    assert linux_report["imported_events"] == 19
    assert linux_report["duplicate_events_skipped"] == 0
    assert windows_report["imported_events"] == 10
    assert windows_report["duplicate_events_skipped"] == 0

    # 2. Verify alerts were generated across all expected detection categories
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 8

    categories_found = {a["category"] for a in alerts}
    assert "brute_force" in categories_found
    assert "password_spraying" in categories_found
    assert "suspicious_auth_sequence" in categories_found
    assert "privileged_account_change" in categories_found
    assert "correlated_compromise" in categories_found

    # 3. Open a Critical alert and verify evidence events, MITRE rationale, and limitations
    target_alert = alerts[0]
    alert_id = target_alert["id"]
    detail_res = client.get(f"/api/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["evidence_events"]) >= 1
    assert detail["mitre_technique_id"]
    assert detail["mitre_mapping_rationale"]
    assert detail["rule_limitations"]
    assert detail["status"] == "new"

    # 4. Acknowledge the alert
    ack_res = client.post(
        f"/api/alerts/{alert_id}/acknowledge",
        json={"analyst": "Alex Rivera", "note": "Triage started; isolating bastion-01."},
    )
    assert ack_res.status_code == 200
    ack_detail = ack_res.json()
    assert ack_detail["status"] == "acknowledged"
    assert ack_detail["acknowledged_by"] == "Alex Rivera"
    assert len(ack_detail["notes"]) == 2  # 1 status_change audit + 1 analyst note

    # 5. Record a disposition and resolve the alert
    patch_res = client.patch(
        f"/api/alerts/{alert_id}",
        json={
            "status": "resolved",
            "disposition": "true_positive_malicious",
            "disposition_reason": "Confirmed SSH brute-force followed by unauthorized sudo group modification.",
            "analyst": "Alex Rivera",
            "note": "Revoked svc_backup credentials and removed support_audit account.",
        },
    )
    assert patch_res.status_code == 200
    resolved_detail = patch_res.json()
    assert resolved_detail["status"] == "resolved"
    assert resolved_detail["disposition"] == "true_positive_malicious"
    assert len(resolved_detail["notes"]) == 4

    # 6. Re-import the exact same sample logs and verify zero duplicate events and preservation of investigation state
    reimport_res = client.post("/api/import/sample/all")
    assert reimport_res.status_code == 200
    reimport_reports = reimport_res.json()
    assert reimport_reports[0]["imported_events"] == 0
    assert reimport_reports[0]["duplicate_events_skipped"] == 19
    assert reimport_reports[1]["imported_events"] == 0
    assert reimport_reports[1]["duplicate_events_skipped"] == 10

    check_again = client.get(f"/api/alerts/{alert_id}").json()
    assert check_again["status"] == "resolved"
    assert check_again["disposition"] == "true_positive_malicious"
    assert len(check_again["notes"]) == 4

    # 7. Verify filtering by status, severity, and host
    resolved_list = client.get("/api/alerts", params={"status": "resolved"}).json()
    assert len(resolved_list) == 1
    assert resolved_list[0]["id"] == alert_id

    bastion_events = client.get("/api/events", params={"host": "bastion-01"}).json()
    assert bastion_events["total"] == 17

    # 8. Verify time range, user, and category filtering
    window_events = client.get(
        "/api/events",
        params={
            "start_time": "2026-10-30T08:12:00Z",
            "end_time": "2026-10-30T08:13:00Z",
            "user": "svc_backup",
        },
    ).json()
    assert window_events["total"] == 7

    spray_alerts = client.get(
        "/api/alerts", params={"category": "password_spraying"}
    ).json()
    assert len(spray_alerts) == 1
    assert spray_alerts[0]["mitre_technique_id"] == "T1110.003"


def test_configurable_thresholds_and_extension_guide_endpoint(
    client: TestClient,
) -> None:
    client.post("/api/import/sample/linux_auth")
    initial_bf = client.get("/api/alerts", params={"category": "brute_force"}).json()
    assert len(initial_bf) == 1  # 6 failed attempts >= default threshold of 5

    # Raise brute_force_failure_threshold to 10 -> uninvestigated brute_force alert is pruned
    current_cfg = client.get("/api/thresholds").json()
    current_cfg["brute_force_failure_threshold"] = 10
    put_res = client.put("/api/thresholds", json=current_cfg)
    assert put_res.status_code == 200
    after_tightening = client.get("/api/alerts", params={"category": "brute_force"}).json()
    assert len(after_tightening) == 0

    # Reset thresholds to defaults -> brute_force alert is re-detected
    reset_res = client.post("/api/thresholds/reset")
    assert reset_res.status_code == 200
    after_reset = client.get("/api/alerts", params={"category": "brute_force"}).json()
    assert len(after_reset) == 1

    # Verify extension point documentation explicitly states no live agent is integrated
    ext_res = client.get("/api/connectors/extension-guide")
    assert ext_res.status_code == 200
    ext_data = ext_res.json()
    assert ext_data["live_agent_integrated"] is False
    assert "LogSourceConnector" in ext_data["extension_interface"]

