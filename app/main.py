"""FastAPI application exposing MCP server capabilities."""
from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import UUID

from fastapi import FastAPI, HTTPException

from .agents import MultiAgentOrchestrator
from .config import AgentStatus, ScanStatus
from .models import (
    AgentConnection,
    AgentRegistration,
    AgentUpdate,
    ExecutionPlan,
    OrchestrationRequest,
    Report,
    ReportCreate,
    ReportUpdate,
    Scan,
    ScanCreate,
    ScanTask,
    ScanUpdate,
    ToolDescriptor,
    VulnerabilityIntelligence,
)
from .reporting import (
    build_markdown,
    render_intelligence_overview,
    render_vulnerability_cards,
    summarize_vulnerabilities,
)
from .store import AgentStore, IntelligenceStore, ReportStore, ScanStore
from .tooling import list_tools, tool_lookup

app = FastAPI(
    title="TornadoAI MCP Server",
    description=(
        "Mission Control Platform for red teaming and vulnerability assessment."
        " Provides orchestration of scans, tool management and reporting."
    ),
    version="0.1.0",
)

scan_store = ScanStore()
report_store = ReportStore()
agent_store = AgentStore()
intelligence_store = IntelligenceStore()
orchestrator = MultiAgentOrchestrator(scan_store, agent_store, intelligence_store)


@app.get("/health", tags=["meta"])
def healthcheck() -> dict:
    """Return application health information."""

    return {"status": "ok", "timestamp": datetime.utcnow()}


@app.get("/tools", response_model=List[ToolDescriptor], tags=["tooling"])
def get_tools() -> List[ToolDescriptor]:
    """Return catalog of integrated tools."""

    return list_tools()


@app.get("/agents", response_model=List[AgentConnection], tags=["agents"])
def list_agents() -> List[AgentConnection]:
    """List registered MCP-compatible agents."""

    return list(agent_store.list())


@app.post("/agents", response_model=AgentConnection, tags=["agents"], status_code=201)
def register_agent(payload: AgentRegistration) -> AgentConnection:
    """Register a new autonomous agent with the platform."""

    return agent_store.register(payload)


@app.get("/agents/{agent_id}", response_model=AgentConnection, tags=["agents"])
def retrieve_agent(agent_id: UUID) -> AgentConnection:
    agent = agent_store.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.patch("/agents/{agent_id}", response_model=AgentConnection, tags=["agents"])
def update_agent(agent_id: UUID, payload: AgentUpdate) -> AgentConnection:
    agent = agent_store.update(agent_id, payload)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/agents/{agent_id}/heartbeat", response_model=AgentConnection, tags=["agents"])
def heartbeat_agent(agent_id: UUID) -> AgentConnection:
    agent = agent_store.heartbeat(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post(
    "/agents/{agent_id}/status/{status}",
    response_model=AgentConnection,
    tags=["agents"],
)
def set_agent_status(agent_id: UUID, status: AgentStatus) -> AgentConnection:
    agent = agent_store.set_status(agent_id, status)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/scans", response_model=Scan, tags=["scans"], status_code=201)
def create_scan(payload: ScanCreate) -> Scan:
    """Create a new scan in draft state."""

    return scan_store.create(payload)


@app.get("/scans", response_model=List[Scan], tags=["scans"])
def list_scans() -> List[Scan]:
    """Return all configured scans."""

    return list(scan_store.list())


@app.get("/scans/{scan_id}", response_model=Scan, tags=["scans"])
def retrieve_scan(scan_id: UUID) -> Scan:
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=Scan, tags=["scans"])
def update_scan(scan_id: UUID, payload: ScanUpdate) -> Scan:
    scan = scan_store.update(scan_id, payload)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.delete("/scans/{scan_id}", response_model=Scan, tags=["scans"])
def delete_scan(scan_id: UUID) -> Scan:
    scan = scan_store.delete(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/scans/{scan_id}/tasks", response_model=Scan, tags=["scans"])
def add_task(scan_id: UUID, task: ScanTask) -> Scan:
    """Add a task to a running or scheduled scan."""

    scan = scan_store.add_task(scan_id, task)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/scans/{scan_id}/status/{status}", response_model=Scan, tags=["scans"])
def set_scan_status(scan_id: UUID, status: ScanStatus) -> Scan:
    """Update lifecycle status of a scan and adjust timestamps accordingly."""

    scan = scan_store.update_status(scan_id, status)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post(
    "/scans/{scan_id}/orchestrate",
    response_model=ExecutionPlan,
    tags=["scans"],
    summary="Generate an autonomous execution plan",
)
def orchestrate_scan(scan_id: UUID, payload: OrchestrationRequest) -> ExecutionPlan:
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        return orchestrator.plan(scan, payload)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get(
    "/scans/{scan_id}/intelligence",
    response_model=VulnerabilityIntelligence,
    tags=["scans"],
    summary="Retrieve vulnerability intelligence for a scan",
)
def get_scan_intelligence(scan_id: UUID) -> VulnerabilityIntelligence:
    intelligence = intelligence_store.get(scan_id)
    if not intelligence:
        raise HTTPException(status_code=404, detail="No intelligence available for scan")
    return intelligence


@app.get(
    "/scans/{scan_id}/intelligence/markdown",
    response_model=str,
    tags=["reports"],
    summary="Render vulnerability intelligence as Markdown",
)
def get_scan_intelligence_markdown(scan_id: UUID) -> str:
    intelligence = intelligence_store.get(scan_id)
    if not intelligence:
        raise HTTPException(status_code=404, detail="No intelligence available for scan")
    overview = render_intelligence_overview(intelligence)
    cards = render_vulnerability_cards(intelligence.cards)
    if cards:
        return f"{overview}\n\n{cards}".strip()
    return overview


@app.post("/reports", response_model=Report, tags=["reports"], status_code=201)
def create_report(payload: ReportCreate) -> Report:
    """Create a custom report for a scan."""

    if not scan_store.get(payload.scan_id):
        raise HTTPException(status_code=404, detail="Scan not found for report")
    return report_store.create(payload)


@app.get("/reports", response_model=List[Report], tags=["reports"])
def list_reports() -> List[Report]:
    return list(report_store.list())


@app.get("/reports/{report_id}", response_model=Report, tags=["reports"])
def retrieve_report(report_id: UUID) -> Report:
    report = report_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.patch("/reports/{report_id}", response_model=Report, tags=["reports"])
def update_report(report_id: UUID, payload: ReportUpdate) -> Report:
    report = report_store.update(report_id, payload)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.delete("/reports/{report_id}", response_model=Report, tags=["reports"])
def delete_report(report_id: UUID) -> Report:
    report = report_store.delete(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get(
    "/reports/{report_id}/markdown",
    response_model=str,
    tags=["reports"],
    summary="Render report as Markdown",
)
def render_report(report_id: UUID) -> str:
    report = report_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return build_markdown(report)


@app.get("/scans/{scan_id}/tasks/suggested", response_model=List[ScanTask], tags=["scans"])
def suggest_tasks(scan_id: UUID) -> List[ScanTask]:
    """Suggest tasks based on requested vulnerabilities and available tooling."""

    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    tools = tool_lookup()
    suggested: List[ScanTask] = []
    for vulnerability in scan.vulnerability_classes:
        if "SQL" in vulnerability.value and "sqlmap" in tools:
            suggested.append(
                ScanTask(
                    name="SQL Injection Probe",
                    description="Run sqlmap against the target to validate injection risks.",
                    tool="sqlmap",
                    parameters={"target": scan.target},
                    required_vulnerabilities=[vulnerability],
                )
            )
        if "INJECTION" in vulnerability.value and "nuclei" in tools:
            suggested.append(
                ScanTask(
                    name="Nuclei Template Sweep",
                    description="Execute targeted nuclei templates matching the vulnerability class.",
                    tool="nuclei",
                    parameters={"target": scan.target},
                    required_vulnerabilities=[vulnerability],
                )
            )
    return suggested


@app.get(
    "/reports/{report_id}/summary",
    response_model=str,
    tags=["reports"],
    summary="Summarize vulnerabilities covered by a report",
)
def report_summary(report_id: UUID) -> str:
    report = report_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return summarize_vulnerabilities(report.sections)
