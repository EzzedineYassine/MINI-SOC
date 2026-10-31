# MINI-SOC — Security Monitoring, Detection, and Incident Investigation Lab

> **Educational Defensive-Security Environment Notice:**
> MINI-SOC is an offline-capable educational log-analysis, detection, and incident-handling workbench. All bundled log files (`linux_auth_incident.log` and `windows_security_incident.jsonl`) are **100% synthetic simulated data**. No live endpoint agent, kernel driver, or offensive/exploitation capability is included.

---

## 1. Architecture & Separation of Concerns

MINI-SOC strictly separates log parsing, normalized models, detection rules, persistence, and API/UI presentation:

- **Explicit Log Parsers & Validation (`backend/app/parsers/`)**
  - [`validator.py`](backend/app/parsers/validator.py): Enforces upload size limits (`2 MB`), line-count caps (`10,000 lines`), UTF-8 validation, multi-format timestamp normalization to UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`), and deterministic SHA-256 event hashing (`compute_event_hash`).
  - [`linux_auth.py`](backend/app/parsers/linux_auth.py): Parses RFC 3164 and ISO-8601 Linux `auth.log` / `syslog` events for `sshd`, `sudo`, `useradd`, `usermod`, `gpasswd`, and `su`.
  - [`windows_jsonl.py`](backend/app/parsers/windows_jsonl.py): Parses structured Windows Security Auditing JSONL exports (`EventID` `4624`, `4625`, `4672`, `4720`, `4728`, `4732`, `4756`, `4740`).
- **Normalized Schema & Domain Models (`backend/app/models.py`)**
  - [`models.py`](backend/app/models.py): Defines `NormalizedEvent`, `AlertSummary`, `AlertDetail`, `InvestigationNote`, `DetectionThresholds`, and `DetectionRuleMetadata`.
- **Structured Detection Rules & Engine (`backend/app/detections/`)**
  - [`rules.py`](backend/app/detections/rules.py): Implements 5 configurable detection rules with explicit MITRE ATT&CK mappings, rationale, and documented limitations.
  - [`engine.py`](backend/app/detections/engine.py): Evaluates all rules over chronological normalized events and persists alerts idempotently.
- **SQLite Persistence Layer (`backend/app/database.py` & `backend/app/repository.py`)**
  - Deduplicates re-imported events via `UNIQUE(event_hash)` and preserves analyst alert investigation states (`status`, `disposition`, `investigation_notes`) via `UNIQUE(alert_fingerprint)`.
- **Documented Log Source Extension Point (`backend/app/connectors/base.py`)**
  - Defines the abstract `LogSourceConnector` interface for future integration with real syslog tailers or Windows Event Forwarding JSONL spoolers.
- **Analyst Console (`frontend/src/`)**
  - Built with React, TypeScript, and Vite in a deep-graphite security operations console aesthetic.

---

## 2. Detection Catalog, MITRE ATT&CK Mappings & Limitations

| Rule ID | Rule Name | Category | Default Severity | MITRE ATT&CK | Rationale | Documented Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE-BF-001` | Repeated Failed Authentication Attempts | `brute_force` | `MEDIUM` / `HIGH` | **T1110.001** (Password Guessing) | High concentration of failed logins against a single account from one source within `brute_force_window_seconds`. | Cannot distinguish a misconfigured service script with stale credentials without asset context; distributed multi-IP or low-and-slow guessing evades single-source windows. |
| `RULE-PS-002` | Multi-Account Password Spraying Activity | `password_spraying` | `HIGH` | **T1110.003** (Password Spraying) | Single source IP failing authentication across `>= password_spray_distinct_users_threshold` distinct accounts within window. | Corporate NAT gateways or shared jump hosts with concurrent user typos can cause benign triggers; rotating proxy IPs per request evades single-IP grouping. |
| `RULE-SEQ-003` | Suspicious Authentication Sequence | `suspicious_auth_sequence` | `HIGH` | **T1078** (Valid Accounts via **T1110**) | Repeated failed logins (`>= suspicious_sequence_failures_before_success`) immediately followed by `auth_success` for the same user/source IP. | A legitimate user mistyping their password multiple times before succeeding can trigger this rule when the threshold is set low. |
| `RULE-PRIV-004` | Privileged Account or Group Modification | `privileged_account_change` | `HIGH` / `CRITICAL` | **T1098** & **T1136.001** & **T1548.003** | Detects local/domain account creation, additions to monitored privileged groups (`sudo`, `wheel`, `Administrators`, `Domain Admins`), or repeated `sudo` failures. | Authorized administrative maintenance produces identical log artifacts unless correlated with change-management tickets. |
| `RULE-CORR-005` | Correlated Compromise Chain | `correlated_compromise` | `CRITICAL` | **T1548.003 / T1098** (Multi-Stage Chain) | Correlates a suspicious login sequence (`RULE-SEQ-003`) with downstream privileged account or group changes on the same host within `correlation_window_seconds`. | Scoped to a single hostname within `correlation_window_seconds`; cross-host lateral movement or delayed execution beyond the window will not link automatically. |

---

## 3. Quickstart (Offline Installation & Demo)

### Backend (Python + FastAPI + Pytest)

```powershell
cd backend
.\.venv\Scripts\pytest -v
.\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend (React + TypeScript + Vite)

```powershell
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser, click **Load Demo Incident Logs** in the top-right header (or visit **Log Ingestion & Connectors**), and explore the generated alerts, evidence timelines, MITRE mappings, threshold tuning, and incident investigation workflow.
