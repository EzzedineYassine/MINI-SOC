from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test_routes.db"
    monkeypatch.setenv("MINI_SOC_DB_PATH", str(db_file))
    init_db(str(db_file))
    return TestClient(app)


def test_cors_headers_for_frontend_origins(client: TestClient) -> None:
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        res = client.get("/api/health", headers={"Origin": origin})
        assert res.status_code == 200
        assert res.headers.get("access-control-allow-origin") == origin
        assert res.headers.get("access-control-allow-credentials") == "true"


def test_trailing_slash_normalization(client: TestClient) -> None:
    endpoints = [
        "/api/health/",
        "/api/dashboard/",
        "/api/alerts/",
        "/api/events/",
        "/api/rules/",
        "/api/thresholds/",
        "/api/samples/",
        "/api/connectors/extension-guide/",
    ]
    for ep in endpoints:
        res = client.get(ep, follow_redirects=False)
        assert res.status_code == 200, f"Expected 200 for {ep}, got {res.status_code}"


def test_seed_and_sample_routes_flexibility(client: TestClient) -> None:
    # Test POST and GET aliases for seed and samples
    res_post_all = client.post("/api/import/sample/all")
    assert res_post_all.status_code == 200

    res_get_seed = client.get("/api/import/seed")
    assert res_get_seed.status_code == 200

    res_samples = client.get("/api/samples")
    assert res_samples.status_code == 200
    samples = res_samples.json()
    assert len(samples) == 2


def test_simulated_full_frontend_initial_load_sequence(client: TestClient) -> None:
    # 1. Trigger demo logs (seed)
    seed_res = client.post("/api/import/sample/all")
    assert seed_res.status_code == 200
    assert len(seed_res.json()) == 2

    # 2. Sequential/Parallel initial load calls made by App.tsx
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 200
    assert dash_res.json()["total_events"] > 0
    assert dash_res.json()["total_alerts"] > 0

    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) > 0

    rules_res = client.get("/api/rules")
    assert rules_res.status_code == 200
    assert len(rules_res.json()) >= 5

    thresh_res = client.get("/api/thresholds")
    assert thresh_res.status_code == 200
    assert "brute_force_failure_threshold" in thresh_res.json()

    events_res = client.get("/api/events?limit=300")
    assert events_res.status_code == 200
    assert events_res.json()["total"] > 0

    samples_res = client.get("/api/samples")
    assert samples_res.status_code == 200

    ext_res = client.get("/api/connectors/extension-guide")
    assert ext_res.status_code == 200
    assert ext_res.json()["live_agent_integrated"] is False

    # 3. Select first alert and load details (line 144 in App.tsx)
    first_alert_id = alerts[0]["id"]
    detail_res = client.get(f"/api/alerts/{first_alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == first_alert_id
    assert len(detail["evidence_events"]) > 0

    # 4. Acknowledge alert
    ack_res = client.post(
        f"/api/alerts/{first_alert_id}/acknowledge",
        json={"analyst": "Alex QA", "note": "Triaged by senior QA."},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "acknowledged"

    # 5. Save investigation disposition
    patch_res = client.patch(
        f"/api/alerts/{first_alert_id}",
        json={
            "status": "resolved",
            "disposition": "educational_simulation",
            "disposition_reason": "Verified simulated SSH brute force sequence.",
            "analyst": "Alex QA",
            "note": "Resolved in QA test suite.",
        },
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "resolved"
