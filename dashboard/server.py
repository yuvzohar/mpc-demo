"""
Dashboard FastAPI server — serves the web UI and real-time WebSocket feed.
"""
from __future__ import annotations
import asyncio
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import BackgroundTasks, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.database import setup_database
from core.mcp_host import MCPHost

from .analyzer import SecurityAnalyzer
from .discovery import MCPDiscovery
from .enforcer import SecurityEnforcer
from .models import PolicyAction, SecurityEvent, SessionInfo, Severity
from .proxy import MCPSecurityProxy

# ── Globals ────────────────────────────────────────────────────────────────────
_mcp_host: Optional[MCPHost] = None
_proxy: Optional[MCPSecurityProxy] = None
_analyzer: Optional[SecurityAnalyzer] = None
_enforcer: Optional[SecurityEnforcer] = None
_discovery: Optional[MCPDiscovery] = None

_event_log: list[SecurityEvent] = []
_sessions: dict[str, SessionInfo] = {}
_ws_clients: set[WebSocket] = set()
_running_scenarios: set[str] = set()

THREAT_NAMES = {
    1: "Prompt Injection / SSRF",
    2: "Auth & Access Abuse",
    3: "Data Exfiltration",
    4: "Privilege Escalation",
    5: "Resource Exhaustion",
    6: "Supply Chain Risk",
    7: "Business Logic Abuse",
    8: "Shadow Agent Activity",
}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demo.db")


# ── Event handling ──────────────────────────────────────────────────────────────

async def _handle_security_event(event: SecurityEvent) -> None:
    _event_log.append(event)
    if len(_event_log) > 500:
        _event_log.pop(0)

    session = _sessions.get(event.session_id)
    if session:
        session.last_activity = event.timestamp
        session.tool_call_count += 1
        session.risk_score = max(session.risk_score, event.risk_score)
        if not event.action_taken.value == "allow":
            if event.action_taken.value == "block":
                session.blocked_count += 1
        if event.anomaly_detected:
            session.anomaly_count += 1

    await _broadcast({"type": "event", "data": event.to_dict()})
    if session:
        await _broadcast({"type": "session_update", "data": session.to_dict()})


async def _broadcast(payload: dict) -> None:
    dead: set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _mcp_host, _proxy, _analyzer, _enforcer, _discovery

    setup_database(DB_PATH)

    _mcp_host = MCPHost(DB_PATH)
    await _mcp_host.start()
    tool_count = len(_mcp_host.list_tools())

    _analyzer = SecurityAnalyzer()
    _enforcer = SecurityEnforcer()
    _discovery = MCPDiscovery(DB_PATH)

    _proxy = MCPSecurityProxy(
        real_host=_mcp_host,
        analyzer=_analyzer,
        enforcer=_enforcer,
        on_event=_handle_security_event,
    )

    _discovery.set_main_server(None)  # will auto-build from scan()

    yield

    await _mcp_host.stop()


# ── App ─────────────────────────────────────────────────────────────────────────

app = FastAPI(title="MCP Security Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def serve_dashboard():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ── WebSocket ───────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_clients.add(ws)

    # Send initial snapshot
    tool_count = len(_mcp_host.list_tools()) if _mcp_host else 19
    await ws.send_json({
        "type": "init",
        "data": {
            "events":   [e.to_dict() for e in _event_log[-100:]],
            "sessions": {k: v.to_dict() for k, v in _sessions.items()},
            "policies": _enforcer.get_all_policies() if _enforcer else [],
            "servers":  _discovery.scan(tool_count) if _discovery else [],
            "circuits": _enforcer.get_circuits() if _enforcer else [],
        },
    })

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(ws)


# ── REST endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/servers")
async def get_servers():
    tool_count = len(_mcp_host.list_tools()) if _mcp_host else 19
    return _discovery.scan(tool_count)


@app.get("/api/events")
async def get_events(limit: int = 100):
    return [e.to_dict() for e in _event_log[-limit:]]


@app.get("/api/sessions")
async def get_sessions_api():
    return {k: v.to_dict() for k, v in _sessions.items()}


@app.get("/api/policies")
async def get_policies():
    return _enforcer.get_all_policies()


class PolicyUpdate(BaseModel):
    action: str


@app.put("/api/policies/{tool_name}")
async def update_policy(tool_name: str, body: PolicyUpdate):
    _enforcer.set_policy(tool_name, body.action)
    policies = _enforcer.get_all_policies()
    await _broadcast({"type": "policies", "data": policies})
    return {"ok": True, "tool": tool_name, "action": body.action}


@app.post("/api/scan")
async def trigger_scan():
    tool_count = len(_mcp_host.list_tools()) if _mcp_host else 19
    servers = _discovery.scan(tool_count)
    await _broadcast({"type": "servers", "data": servers})
    return servers


@app.post("/api/circuits/{session_id}/reset")
async def reset_circuit(session_id: str):
    _enforcer.reset_circuit(session_id)
    circuits = _enforcer.get_circuits()
    await _broadcast({"type": "circuits", "data": circuits})
    return {"ok": True}


@app.post("/api/demo/run/{threat_number}")
async def run_threat_demo(threat_number: int, background_tasks: BackgroundTasks):
    if threat_number not in THREAT_NAMES:
        return JSONResponse(status_code=400, content={"error": "Invalid threat number"})

    session_id = f"t{threat_number:02d}_{uuid.uuid4().hex[:6]}"
    _sessions[session_id] = SessionInfo(
        session_id=session_id,
        threat_scenario=THREAT_NAMES[threat_number],
        started_at=datetime.now(),
        last_activity=datetime.now(),
    )
    await _broadcast({"type": "session_update", "data": _sessions[session_id].to_dict()})
    background_tasks.add_task(_run_scenario_bg, threat_number, session_id)
    return {"session_id": session_id, "status": "started"}


async def _run_scenario_bg(threat_number: int, session_id: str) -> None:
    from threats.t01_prompt_injection    import T01PromptInjection
    from threats.t02_auth_abuse          import T02AuthAbuse
    from threats.t03_data_exfiltration   import T03DataExfiltration
    from threats.t04_privilege_escalation import T04PrivilegeEscalation
    from threats.t05_resource_exhaustion  import T05ResourceExhaustion
    from threats.t06_supply_chain         import T06SupplyChain
    from threats.t07_business_logic       import T07BusinessLogicAbuse
    from threats.t08_shadow_agent         import T08ShadowAgent

    scenario_map = {
        1: T01PromptInjection,
        2: T02AuthAbuse,
        3: T03DataExfiltration,
        4: T04PrivilegeEscalation,
        5: T05ResourceExhaustion,
        6: T06SupplyChain,
        7: T07BusinessLogicAbuse,
        8: T08ShadowAgent,
    }

    _proxy.set_session(session_id)
    _running_scenarios.add(session_id)

    try:
        cls = scenario_map[threat_number]
        # Pass proxy as mcp_host — it satisfies the same interface
        scenario = cls(mcp_host=_proxy, demo_mode=True)
        # Suppress Rich terminal output — dashboard is the display
        import io
        from rich.console import Console
        from core import display as disp
        old_console = disp.console
        disp.console = Console(file=io.StringIO(), highlight=False)
        try:
            await scenario.run()
        finally:
            disp.console = old_console
    except Exception as exc:
        await _broadcast({
            "type": "error",
            "data": {"session_id": session_id, "error": str(exc)},
        })
    finally:
        _running_scenarios.discard(session_id)
        if session_id in _sessions:
            _sessions[session_id].status = "completed"
            await _broadcast({"type": "session_update", "data": _sessions[session_id].to_dict()})


# ── External ingest (used by main.py simulator) ─────────────────────────────────

class IngestSession(BaseModel):
    session_id: str
    threat_scenario: Optional[str] = None
    status: str = "active"


class IngestEvent(BaseModel):
    id: str
    timestamp: str
    session_id: str
    tool_name: str
    arguments: dict
    result_preview: str = ""
    risk_score: int
    severity: str
    anomaly_detected: bool
    pattern_matched: Optional[str] = None
    threat_name: Optional[str] = None
    action_taken: str
    impact: str
    handled_by: str


@app.post("/api/sessions/ingest")
async def ingest_session(body: IngestSession):
    """Create or update a session pushed from the external CLI simulator."""
    if body.session_id not in _sessions:
        _sessions[body.session_id] = SessionInfo(
            session_id=body.session_id,
            threat_scenario=body.threat_scenario,
            started_at=datetime.now(),
            last_activity=datetime.now(),
        )
    else:
        _sessions[body.session_id].status = body.status
        _sessions[body.session_id].last_activity = datetime.now()

    await _broadcast({"type": "session_update", "data": _sessions[body.session_id].to_dict()})
    return {"ok": True}


@app.post("/api/events/ingest")
async def ingest_event(body: IngestEvent):
    """Ingest a security event pushed from the external CLI simulator."""
    # Auto-create session if it doesn't exist yet
    if body.session_id not in _sessions:
        _sessions[body.session_id] = SessionInfo(
            session_id=body.session_id,
            threat_scenario=None,
            started_at=datetime.now(),
            last_activity=datetime.now(),
        )

    event = SecurityEvent(
        id=body.id,
        timestamp=datetime.fromisoformat(body.timestamp),
        session_id=body.session_id,
        tool_name=body.tool_name,
        arguments=body.arguments,
        result=body.result_preview,
        risk_score=body.risk_score,
        severity=Severity(body.severity),
        anomaly_detected=body.anomaly_detected,
        pattern_matched=body.pattern_matched,
        threat_name=body.threat_name,
        action_taken=PolicyAction(body.action_taken),
        impact=body.impact,
        handled_by=body.handled_by,
    )
    await _handle_security_event(event)
    return {"ok": True}
