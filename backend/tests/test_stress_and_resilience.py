from __future__ import annotations

import concurrent.futures
import json
import pytest
from fastapi.testclient import TestClient

from app.database import get_connection, init_db
from app.detections.rules import (
    detect_brute_force,
    detect_correlated_compromise_chains,
    detect_password_spraying,
    detect_privileged_account_changes,
    detect_suspicious_auth_sequences,
)
from app.main import app
from app.models import DetectionThresholds, EventType, SourceFormat
from app.parsers.linux_auth import parse_linux_auth_log
from app.parsers.validator import (
    LogValidationError,
    normalize_timestamp,
    validate_raw_content,
)
from app.parsers.windows_jsonl import parse_windows_jsonl
from app.repository import SecurityRepository


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "stress_test.db"
    monkeypatch.setenv("MINI_SOC_DB_PATH", str(db_file))
    init_db(str(db_file))
    return TestClient(app)


def test_parser_stress_with_malformed_and_hostile_inputs() -> None:
    # 1. Null bytes in Linux auth log
    dirty_linux = (
        "Oct 30 10:00:00 host-a sshd[10]: Failed password for root from 1.1.1.1 port 22 ssh2\x00\n"
        "\x00Oct 30 10:00:01 host-a sshd[11]: Accepted password for root from 1.1.1.1 port 22 ssh2\n"
        "GARBAGE_LINE_NO_HEADER\n"
        "Oct 30 10:00:02 host-a unknown_daemon[99]: Something completely unrecognizable\n"
    )
    res_linux = parse_linux_auth_log(dirty_linux)
    assert res_linux.total_lines_processed == 4
    assert len(res_linux.events) == 2
    assert len(res_linux.errors) == 2
    # Ensure null bytes were safely removed from parsed event
    assert "\x00" not in res_linux.events[0].raw_event

    # 2. Windows JSONL with null bytes, UTF-8 BOM, missing fields, broken JSON, bad types
    bom_and_garbage_jsonl = (
        '{"TimeCreated":"2026-10-30T10:00:00Z","Computer":"DC-01","EventID":4625,"TargetUserName":"admin","IpAddress":"10.0.0.1"}\n'
        '{"TimeCreated": null, "Computer": "DC-01", "EventID": 4625}\n'
        '{"TimeCreated": "2026-10-30T10:00:02Z", "Computer": null, "EventID": 4625}\n'
        '{"TimeCreated": "2026-10-30T10:00:03Z", "Computer": "DC-01", "EventID": "NOT_AN_INT"}\n'
        '{"TimeCreated": "2026-10-30T10:00:04Z", "Computer": "DC-01", "EventID": 99999}\n'
        '{"TimeCreated": "2026-10-30T10:00:05Z", "Computer": "DC-01", "EventID": 4624, "TargetUserName": 12345, "IpAddress": "127.0.0.1\x00"}\n'
        '{"corrupted_json: \n'
        '[]\n'
    )
    res_win = parse_windows_jsonl(bom_and_garbage_jsonl)
    assert res_win.total_lines_processed == 8
    # Events 1 and 6 should parse cleanly
    assert len(res_win.events) == 2
    assert len(res_win.errors) == 6
    assert res_win.events[0].user == "admin"
    assert res_win.events[1].user == "12345"


def test_timestamp_stress_and_epoch_support() -> None:
    # Epoch timestamp in seconds
    assert normalize_timestamp("1761814800") == "2025-10-30T09:00:00Z"
    # Epoch timestamp in milliseconds
    assert normalize_timestamp("1761814800000") == "2025-10-30T09:00:00Z"
    # Date with slashes
    assert normalize_timestamp("2026/10/30 08:15:02Z") == "2026-10-30T08:15:02Z"
    # Date enclosed in brackets or quotes
    assert normalize_timestamp('[2026-10-30T08:15:02Z]') == "2026-10-30T08:15:02Z"
    assert normalize_timestamp('"2026-10-30T08:15:02Z"') == "2026-10-30T08:15:02Z"

    with pytest.raises(ValueError):
        normalize_timestamp("not-valid")


def test_utf8_bom_validation() -> None:
    # UTF-8 BOM prefixed payload
    bom_bytes = b'\xef\xbb\xbf{"TimeCreated":"2026-10-30T10:00:00Z","Computer":"DC-01","EventID":4624,"TargetUserName":"admin"}'
    text = validate_raw_content(bom_bytes)
    assert not text.startswith('\ufeff')
    res = parse_windows_jsonl(text)
    assert len(res.events) == 1
    assert res.events[0].user == "admin"


def test_sqlite_concurrent_read_write_no_lock(tmp_path) -> None:
    db_file = tmp_path / "concurrent_stress.db"
    init_db(str(db_file))
    repo = SecurityRepository(str(db_file))

    # Concurrently insert events from 8 worker threads to stress test SQLite WAL and locking
    def worker_insert(worker_id: int):
        lines = [
            f"2026-10-30T10:0{worker_id}:0{i}Z host-{worker_id} sshd[{1000 + i}]: Failed password for user{worker_id} from 10.0.0.{worker_id} port {5000+i} ssh2"
            for i in range(10)
        ]
        parsed = parse_linux_auth_log("\n".join(lines))
        return repo.insert_events_idempotent(parsed.events)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_insert, wid) for wid in range(8)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    total_inserted = sum(r[0] for r in results)
    assert total_inserted == 80
    events, count = repo.list_events(limit=100)
    assert count == 80


def test_rules_boundary_conditions_and_all_five_categories(tmp_path) -> None:
    db_file = tmp_path / "rules_stress.db"
    repo = SecurityRepository(str(db_file))
    thresholds = DetectionThresholds(
        brute_force_failure_threshold=3,
        brute_force_window_seconds=60,
        password_spray_distinct_users_threshold=3,
        password_spray_window_seconds=120,
        suspicious_sequence_failures_before_success=2,
        suspicious_sequence_window_seconds=60,
        sudo_failure_threshold=2,
        correlation_window_seconds=300,
        monitored_privileged_groups=["sudo", "Administrators"],
    )

    # 1. RULE-BF-001 (Threshold = 3 failures)
    # 2 failures -> 0 alerts
    log_bf_below = "\n".join([
        "2026-10-30T10:00:00Z srv-1 sshd[1]: Failed password for alice from 192.168.1.50 port 4001 ssh2",
        "2026-10-30T10:00:30Z srv-1 sshd[2]: Failed password for alice from 192.168.1.50 port 4002 ssh2",
    ])
    repo.insert_events_idempotent(parse_linux_auth_log(log_bf_below).events)
    stored = repo.get_all_events_chronological()
    assert len(detect_brute_force(stored, thresholds)) == 0

    # 3rd failure at exactly 10:01:00Z (60s from first) -> triggers 1 alert
    log_bf_hit = "2026-10-30T10:01:00Z srv-1 sshd[3]: Failed password for alice from 192.168.1.50 port 4003 ssh2"
    repo.insert_events_idempotent(parse_linux_auth_log(log_bf_hit).events)
    stored = repo.get_all_events_chronological()
    bf_alerts = detect_brute_force(stored, thresholds)
    assert len(bf_alerts) == 1
    assert bf_alerts[0].rule_id == "RULE-BF-001"

    # 2. RULE-PS-002 (Password Spraying across 3 distinct users from single IP)
    # 2 distinct users -> 0 alerts
    log_ps_below = "\n".join([
        "2026-10-30T10:05:00Z srv-1 sshd[10]: Failed password for user_a from 198.51.100.99 port 5001 ssh2",
        "2026-10-30T10:05:10Z srv-1 sshd[11]: Failed password for user_b from 198.51.100.99 port 5002 ssh2",
    ])
    repo.insert_events_idempotent(parse_linux_auth_log(log_ps_below).events)
    stored = repo.get_all_events_chronological()
    assert len(detect_password_spraying(stored, thresholds)) == 0

    # 3rd distinct user from same IP -> triggers 1 password spray alert
    log_ps_hit = "2026-10-30T10:05:20Z srv-1 sshd[12]: Failed password for user_c from 198.51.100.99 port 5003 ssh2"
    repo.insert_events_idempotent(parse_linux_auth_log(log_ps_hit).events)
    stored = repo.get_all_events_chronological()
    ps_alerts = detect_password_spraying(stored, thresholds)
    assert len(ps_alerts) == 1
    assert ps_alerts[0].rule_id == "RULE-PS-002"

    # 3. RULE-SEQ-003 (Suspicious Sequence: >= 2 failures followed by login)
    log_seq = "\n".join([
        "2026-10-30T10:10:00Z srv-1 sshd[20]: Failed password for target_x from 203.0.113.5 port 6001 ssh2",
        "2026-10-30T10:10:15Z srv-1 sshd[21]: Failed password for target_x from 203.0.113.5 port 6002 ssh2",
        "2026-10-30T10:10:30Z srv-1 sshd[22]: Accepted password for target_x from 203.0.113.5 port 6003 ssh2",
    ])
    repo.insert_events_idempotent(parse_linux_auth_log(log_seq).events)
    stored = repo.get_all_events_chronological()
    seq_alerts = detect_suspicious_auth_sequences(stored, thresholds)
    assert len(seq_alerts) == 1
    assert seq_alerts[0].rule_id == "RULE-SEQ-003"

    # 4. RULE-PRIV-004 (Privileged Account Change & Sudo Escalation)
    log_priv = "\n".join([
        "2026-10-30T10:11:00Z srv-1 useradd[30]: new user: name=backdoor_user, UID=1099, GID=1099, home=/home/backdoor, shell=/bin/bash",
        "2026-10-30T10:11:10Z srv-1 usermod[31]: add 'target_x' to group 'sudo'",
        "2026-10-30T10:11:20Z srv-1 sudo[32]: target_x : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id",
        "2026-10-30T10:11:30Z srv-1 sudo[33]: target_x : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id",
    ])
    repo.insert_events_idempotent(parse_linux_auth_log(log_priv).events)
    stored = repo.get_all_events_chronological()
    priv_alerts = detect_privileged_account_changes(stored, thresholds)
    assert len(priv_alerts) >= 3  # account_created + group_membership_change + sudo_failure threshold met

    # 5. RULE-CORR-005 (Correlated Multi-Stage Compromise Chain: Seq + Priv Change on same host)
    corr_alerts = detect_correlated_compromise_chains(stored, seq_alerts, thresholds)
    assert len(corr_alerts) == 1
    assert corr_alerts[0].rule_id == "RULE-CORR-005"
    assert corr_alerts[0].severity.value == "critical"


def test_repeated_import_idempotency_and_investigation_preservation(client: TestClient) -> None:
    # Step 1: Import sample logs 3 times in a row
    for _ in range(3):
        res = client.post("/api/import/sample/all")
        assert res.status_code == 200

    dash = client.get("/api/dashboard").json()
    total_events = dash["total_events"]
    total_alerts = dash["total_alerts"]
    assert total_events == 29
    assert total_alerts == 12

    # Step 2: Acknowledge and resolve Alert #1
    alerts = client.get("/api/alerts").json()
    first_alert = alerts[0]
    alert_id = first_alert["id"]

    client.post(
        f"/api/alerts/{alert_id}/acknowledge",
        json={"analyst": "Lead DevSecOps", "note": "Triage verified."},
    )
    client.patch(
        f"/api/alerts/{alert_id}",
        json={
            "status": "resolved",
            "disposition": "true_positive_malicious",
            "disposition_reason": "Confirmed multi-stage compromise chain.",
            "analyst": "Lead DevSecOps",
            "note": "Host isolated and credentials rotated.",
        },
    )

    # Step 3: Re-import logs 2 MORE times
    for _ in range(2):
        re_res = client.post("/api/import/sample/all")
        assert re_res.status_code == 200
        # Check that 0 events were re-imported
        for rep in re_res.json():
            assert rep["imported_events"] == 0

    # Step 4: Verify counts have NOT doubled, and alert investigation state was 100% preserved
    dash_after = client.get("/api/dashboard").json()
    assert dash_after["total_events"] == total_events
    assert dash_after["total_alerts"] == total_alerts

    alert_after = client.get(f"/api/alerts/{alert_id}").json()
    assert alert_after["status"] == "resolved"
    assert alert_after["disposition"] == "true_positive_malicious"
    assert alert_after["disposition_reason"] == "Confirmed multi-stage compromise chain."
    assert len(alert_after["notes"]) >= 3
