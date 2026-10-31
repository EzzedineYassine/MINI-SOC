# MINI-SOC: Security Monitoring, Detection & Incident Investigation Lab

**MINI-SOC** is an educational, defensive-security log analysis workbench engineered for security students, blue-team analysts, and small teams. It delivers an end-to-end incident handling workflow—from ingesting multi-platform raw telemetry and evaluating MITRE ATT&CK-aligned detections, to triaging alerts, auditing underlying evidence chains, and documenting analyst notes—all operating completely offline.

---

### 🚀 Key Highlights

* **Cross-Platform Telemetry Normalization**: Ingests traditional Linux `auth.log` records (SSH, sudo, account modifications) and Windows Security Event JSONL exports (Event IDs 4624, 4625, 4672, 4720, 4732). Normalizes disparate fields into consistent UTC timestamps, hosts, event types, actors, and network indicators.
* **Deterministic Event Hashing**: Uses SHA-256 event fingerprinting to ensure idempotent data ingestion. Re-importing files skips existing records without duplicating telemetry or overwriting active investigation workflows.
* **Structured, Configurable Detection Engine**:
  * `RULE-BF-001`: Repeated Failed Authentication Attempts (MITRE T1110.001)
  * `RULE-PS-002`: Multi-Account Password Spraying (MITRE T1110.003)
  * `RULE-SEQ-003`: Suspicious Auth Sequence / Post-Brute Force Login (MITRE T1078)
  * `RULE-PRIV-004`: Privileged Account/Group Escalation (MITRE T1098, T1136.001, T1548.003)
  * `RULE-CORR-005`: Correlated Multi-Stage Compromise Chains
* **Analyst Investigation Workbench**: Inspect linked evidence events, assign alert dispositions (*True Positive - Malicious*, *False Positive*, etc.), trace chronological event timelines, and record auditable investigation notes.
* **Runtime Threshold Customization**: Modify failure counts, sliding windows, and privileged group lists on the fly without changing code.
* **Offline & Ready-to-Run**: Bundles pre-built, realistic synthetic intrusion scenarios for Linux and Windows domain controllers—zero production network agent required.

---

### 🛠️ Architecture

| Layer | Technologies | Key Design Features |
| :--- | :--- | :--- |
| **Backend** | Python 3.14, FastAPI, Pydantic v2 | Modular separation of log parsers, detection algorithms, and REST APIs with strict input validation. |
| **Data Layer** | SQLite3 (WAL Mode) | Idempotent event deduplication via hash indexes, persistent alerts, notes, and thresholds. |
| **Frontend** | React 18, TypeScript, Vite | Dark-graphite SOC UI, multi-facet event filtering, 10-minute UTC activity timeline. |
| **Testing** | Pytest | Comprehensive test suite covering malformed lines, boundary conditions, and route parity. |

---

### ⚡ Quick Start

#### 1. Clone & Setup Backend
```bash
git clone [https://github.com/EzzedineYassine/MINI-SOC.git](https://github.com/EzzedineYassine/MINI-SOC.git)
cd MINI-SOC/backend

# Create virtual environment & install dependencies
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload






#Setup Frontend
Bash
cd ../frontend
npm install
npm run dev
