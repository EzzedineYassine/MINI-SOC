from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .connectors.base import LocalBatchFileConnector, get_connector_extension_guide
from .database import init_db
from .detections.engine import DetectionEngine
from .detections.rules import get_rule_metadata_list
from .models import (
    AlertDetail,
    AlertSummary,
    AlertStatus,
    AlertUpdateRequest,
    DetectionRuleMetadata,
    DetectionThresholds,
    ImportResponse,
    InvestigationNoteCreate,
    SourceFormat,
)
from .parsers.validator import LogValidationError, detect_source_format
from .repository import SecurityRepository

SAMPLE_LOGS_DIR = Path(__file__).resolve().parent.parent / "sample_logs"

BUNDLED_SAMPLES: Dict[str, Dict[str, Any]] = {
    "linux_auth": {
        "id": "linux_auth",
        "title": "Simulated Linux SSH & Sudo Intrusion (linux_auth_incident.log)",
        "filename": "linux_auth_incident.log",
        "source_format": SourceFormat.LINUX_AUTH,
        "is_simulated": True,
        "description": (
            "Synthetic Linux syslog/auth.log scenario covering SSH password spraying from 198.51.100.42, "
            "targeted brute-force against svc_backup from 203.0.113.88 followed by a successful login, "
            "unauthorized sudo attempts, account creation (support_audit), and sudo group elevation."
        ),
    },
    "windows_security": {
        "id": "windows_security",
        "title": "Simulated Windows Domain Controller Event Export (windows_security_incident.jsonl)",
        "filename": "windows_security_incident.jsonl",
        "source_format": SourceFormat.WINDOWS_JSONL,
        "is_simulated": True,
        "description": (
            "Synthetic Windows Security Auditing JSONL export (Event IDs 4624, 4625, 4672, 4720, 4732) "
            "demonstrating repeated RDP logon failures against j.miller on WIN-DC01 followed by a successful "
            "logon, special privilege assignment, creation of svc_sync_adm, and addition to Administrators."
        ),
    },
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="MINI-SOC — Security Monitoring, Detection & Incident Investigation Lab",
    description=(
        "Educational defensive-security monitoring workflow that ingests Linux auth logs and Windows "
        "Security JSONL exports, normalizes events, runs configurable MITRE ATT&CK-mapped detections, "
        "and supports structured alert triage and investigation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def normalize_trailing_slash_middleware(request, call_next):
    path = request.scope.get("path", "")
    if len(path) > 1 and path.endswith("/"):
        request.scope["path"] = path.rstrip("/")
    return await call_next(request)


def get_repo() -> SecurityRepository:
    return SecurityRepository()


class RawLogImportRequest(BaseModel):
    filename: str = Field(default="manual_paste.log", min_length=1, max_length=120)
    content: str = Field(..., min_length=1)
    source_format: Optional[SourceFormat] = None
    is_simulated: bool = True


def _execute_import(
    repo: SecurityRepository,
    file_bytes: bytes,
    source_name: str,
    explicit_format: Optional[SourceFormat],
    is_simulated: bool,
) -> ImportResponse:
    try:
        connector = LocalBatchFileConnector(
            file_bytes=file_bytes,
            filename=source_name,
            source_format=explicit_format,
            is_simulated=is_simulated,
        )
        parse_result = connector.fetch_and_parse()
    except LogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    resolved_format = explicit_format or detect_source_format(
        file_bytes.decode("utf-8", errors="ignore"), source_name
    )
    inserted, skipped = repo.insert_events_idempotent(parse_result.events)
    engine = DetectionEngine(repo)
    new_alerts, total_alerts = engine.evaluate_all()

    repo.record_import_history(
        source_name=source_name,
        source_format=resolved_format,
        is_simulated=is_simulated,
        total_lines=parse_result.total_lines_processed,
        imported_events=inserted,
        duplicate_events=skipped,
        malformed_lines=len(parse_result.errors),
        new_alerts=new_alerts,
    )

    return ImportResponse(
        source_name=source_name,
        source_format=resolved_format,
        is_simulated=is_simulated,
        total_lines_processed=parse_result.total_lines_processed,
        imported_events=inserted,
        duplicate_events_skipped=skipped,
        malformed_lines=len(parse_result.errors),
        parse_errors=parse_result.errors,
        new_alerts_generated=new_alerts,
        total_active_alerts=total_alerts,
    )


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "mini-soc-backend",
        "environment": "educational_defensive_lab",
        "offline_ready": True,
        "live_agent_integrated": False,
    }


@app.get("/api/dashboard")
def get_dashboard(repo: SecurityRepository = Depends(get_repo)) -> Dict[str, Any]:
    return repo.get_dashboard_summary()


@app.get("/api/samples")
def list_samples() -> List[Dict[str, Any]]:
    samples_out: List[Dict[str, Any]] = []
    for key, meta in BUNDLED_SAMPLES.items():
        path = SAMPLE_LOGS_DIR / meta["filename"]
        preview_lines: List[str] = []
        if path.exists():
            raw_text = path.read_text(encoding="utf-8")
            preview_lines = [
                ln for ln in raw_text.splitlines() if ln.strip() and not ln.startswith("#")
            ][:4]
        samples_out.append(
            {
                **meta,
                "available": path.exists(),
                "preview_lines": preview_lines,
            }
        )
    return samples_out


@app.api_route("/api/import/sample/{sample_id}", methods=["GET", "POST"], response_model=List[ImportResponse])
def import_bundled_sample(
    sample_id: str,
    repo: SecurityRepository = Depends(get_repo),
) -> List[ImportResponse]:
    if sample_id in ("all", "seed"):
        target_keys = list(BUNDLED_SAMPLES.keys())
    elif sample_id in BUNDLED_SAMPLES:
        target_keys = [sample_id]
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown sample dataset '{sample_id}'. Valid options: linux_auth, windows_security, all, seed.",
        )

    responses: List[ImportResponse] = []
    for key in target_keys:
        meta = BUNDLED_SAMPLES[key]
        path = SAMPLE_LOGS_DIR / meta["filename"]
        if not path.exists():
            raise HTTPException(
                status_code=500,
                detail=f"Sample log file '{meta['filename']}' not found on disk.",
            )
        responses.append(
            _execute_import(
                repo=repo,
                file_bytes=path.read_bytes(),
                source_name=meta["filename"],
                explicit_format=meta["source_format"],
                is_simulated=True,
            )
        )
    return responses


@app.api_route("/api/import/seed", methods=["GET", "POST"], response_model=List[ImportResponse])
def import_seed_data(
    repo: SecurityRepository = Depends(get_repo),
) -> List[ImportResponse]:
    return import_bundled_sample("all", repo=repo)


@app.post("/api/import/upload", response_model=ImportResponse)
async def import_uploaded_file(
    file: UploadFile = File(...),
    source_format: Optional[SourceFormat] = Form(default=None),
    is_simulated: bool = Form(default=True),
    repo: SecurityRepository = Depends(get_repo),
) -> ImportResponse:
    content_bytes = await file.read()
    filename = file.filename or "uploaded.log"
    return _execute_import(
        repo=repo,
        file_bytes=content_bytes,
        source_name=filename,
        explicit_format=source_format,
        is_simulated=is_simulated,
    )


@app.post("/api/import/raw", response_model=ImportResponse)
def import_raw_text(
    req: RawLogImportRequest,
    repo: SecurityRepository = Depends(get_repo),
) -> ImportResponse:
    return _execute_import(
        repo=repo,
        file_bytes=req.content.encode("utf-8"),
        source_name=req.filename,
        explicit_format=req.source_format,
        is_simulated=req.is_simulated,
    )


@app.get("/api/events")
def list_events(
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    host: Optional[str] = Query(default=None),
    user: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=250, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    repo: SecurityRepository = Depends(get_repo),
) -> Dict[str, Any]:
    events, total = repo.list_events(
        start_time=start_time,
        end_time=end_time,
        host=host,
        user=user,
        event_type=event_type,
        source_ip=source_ip,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [e.model_dump() for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/alerts", response_model=List[AlertSummary])
def list_alerts(
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    host: Optional[str] = Query(default=None),
    user: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    repo: SecurityRepository = Depends(get_repo),
) -> List[AlertSummary]:
    return repo.list_alerts(
        start_time=start_time,
        end_time=end_time,
        host=host,
        user=user,
        severity=severity,
        status=status,
        category=category,
        search=search,
    )


@app.get("/api/alerts/{alert_id}", response_model=AlertDetail)
def get_alert_detail(
    alert_id: int,
    repo: SecurityRepository = Depends(get_repo),
) -> AlertDetail:
    detail = repo.get_alert_detail(alert_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return detail


@app.patch("/api/alerts/{alert_id}", response_model=AlertDetail)
def update_alert(
    alert_id: int,
    req: AlertUpdateRequest,
    repo: SecurityRepository = Depends(get_repo),
) -> AlertDetail:
    updated = repo.update_alert_investigation(alert_id, req)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return updated


class AcknowledgeRequest(BaseModel):
    analyst: str = Field(default="SOC Analyst", min_length=1, max_length=80)
    note: Optional[str] = Field(default=None, max_length=2000)


@app.post("/api/alerts/{alert_id}/acknowledge", response_model=AlertDetail)
def acknowledge_alert(
    alert_id: int,
    req: AcknowledgeRequest = AcknowledgeRequest(),
    repo: SecurityRepository = Depends(get_repo),
) -> AlertDetail:
    updated = repo.update_alert_investigation(
        alert_id,
        AlertUpdateRequest(
            status=AlertStatus.ACKNOWLEDGED,
            analyst=req.analyst,
            note=req.note,
        ),
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return updated


@app.post("/api/alerts/{alert_id}/notes", response_model=AlertDetail)
def add_note_to_alert(
    alert_id: int,
    req: InvestigationNoteCreate,
    repo: SecurityRepository = Depends(get_repo),
) -> AlertDetail:
    updated = repo.add_investigation_note(alert_id, req)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return updated


@app.get("/api/rules", response_model=List[DetectionRuleMetadata])
def list_detection_rules(
    repo: SecurityRepository = Depends(get_repo),
) -> List[DetectionRuleMetadata]:
    thresholds = repo.get_thresholds()
    alerts = repo.list_alerts()
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a.rule_id] = counts.get(a.rule_id, 0) + 1
    return get_rule_metadata_list(thresholds, counts)


@app.get("/api/thresholds", response_model=DetectionThresholds)
def get_thresholds(
    repo: SecurityRepository = Depends(get_repo),
) -> DetectionThresholds:
    return repo.get_thresholds()


@app.put("/api/thresholds")
def update_thresholds(
    thresholds: DetectionThresholds,
    repo: SecurityRepository = Depends(get_repo),
) -> Dict[str, Any]:
    saved = repo.save_thresholds(thresholds)
    engine = DetectionEngine(repo)
    new_alerts, total_alerts = engine.evaluate_all(
        thresholds=saved, prune_uninvestigated_stale=True
    )
    return {
        "thresholds": saved.model_dump(),
        "new_alerts_generated": new_alerts,
        "total_active_alerts": total_alerts,
    }


@app.post("/api/thresholds/reset")
def reset_thresholds(
    repo: SecurityRepository = Depends(get_repo),
) -> Dict[str, Any]:
    defaults = DetectionThresholds()
    saved = repo.save_thresholds(defaults)
    engine = DetectionEngine(repo)
    new_alerts, total_alerts = engine.evaluate_all(
        thresholds=saved, prune_uninvestigated_stale=True
    )
    return {
        "thresholds": saved.model_dump(),
        "new_alerts_generated": new_alerts,
        "total_active_alerts": total_alerts,
    }


@app.get("/api/connectors/extension-guide")
def get_extension_guide() -> Dict[str, Any]:
    return get_connector_extension_guide()


@app.post("/api/workspace/reset")
def reset_workspace(
    repo: SecurityRepository = Depends(get_repo),
) -> Dict[str, str]:
    repo.reset_workspace()
    return {"status": "cleared"}
