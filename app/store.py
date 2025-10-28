"""In-memory persistence layer for scans and reports."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, Iterable, Optional
from uuid import UUID

from .config import AgentStatus, ScanStatus
from .models import (
    AgentConnection,
    AgentRegistration,
    AgentUpdate,
    Report,
    ReportCreate,
    ReportUpdate,
    Scan,
    ScanCreate,
    ScanTask,
    ScanUpdate,
    VulnerabilityIntelligence,
)


class ScanStore:
    """Stores scan jobs and supports lifecycle operations."""

    def __init__(self) -> None:
        self._scans: Dict[UUID, Scan] = {}

    def list(self) -> Iterable[Scan]:
        return self._scans.values()

    def get(self, scan_id: UUID) -> Optional[Scan]:
        return self._scans.get(scan_id)

    def create(self, payload: ScanCreate) -> Scan:
        scan = Scan(**payload.dict())
        self._scans[scan.id] = scan
        return scan

    def update(self, scan_id: UUID, payload: ScanUpdate) -> Optional[Scan]:
        scan = self.get(scan_id)
        if not scan:
            return None
        update_data = payload.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scan, field, value)
        scan.updated_at = datetime.utcnow()
        return scan

    def delete(self, scan_id: UUID) -> Optional[Scan]:
        return self._scans.pop(scan_id, None)

    def add_task(self, scan_id: UUID, task: ScanTask) -> Optional[Scan]:
        scan = self.get(scan_id)
        if not scan:
            return None
        scan.tasks.append(task)
        scan.updated_at = datetime.utcnow()
        return scan

    def update_status(self, scan_id: UUID, status: ScanStatus) -> Optional[Scan]:
        scan = self.get(scan_id)
        if not scan:
            return None
        now = datetime.utcnow()
        if status == ScanStatus.RUNNING:
            scan.started_at = now
        if status in {ScanStatus.COMPLETED, ScanStatus.CANCELLED}:
            scan.completed_at = now
        scan.status = status
        scan.updated_at = now
        return scan


class ReportStore:
    """Stores custom reports linked to scans."""

    def __init__(self) -> None:
        self._reports: Dict[UUID, Report] = {}

    def list(self) -> Iterable[Report]:
        return self._reports.values()

    def get(self, report_id: UUID) -> Optional[Report]:
        return self._reports.get(report_id)

    def create(self, payload: ReportCreate) -> Report:
        report = Report(**payload.dict())
        self._reports[report.id] = report
        return report

    def update(self, report_id: UUID, payload: ReportUpdate) -> Optional[Report]:
        report = self.get(report_id)
        if not report:
            return None
        for field, value in payload.dict(exclude_unset=True).items():
            setattr(report, field, value)
        report.updated_at = datetime.utcnow()
        return report

    def delete(self, report_id: UUID) -> Optional[Report]:
        return self._reports.pop(report_id, None)


class AgentStore:
    """Tracks connected agents and their operational state."""

    def __init__(self) -> None:
        self._agents: Dict[UUID, AgentConnection] = {}

    def list(self) -> Iterable[AgentConnection]:
        return self._agents.values()

    def get(self, agent_id: UUID) -> Optional[AgentConnection]:
        return self._agents.get(agent_id)

    def register(self, payload: AgentRegistration) -> AgentConnection:
        agent = AgentConnection(**payload.dict(exclude_none=True))
        agent.status = AgentStatus.READY
        self._agents[agent.id] = agent
        return agent

    def update(self, agent_id: UUID, payload: AgentUpdate) -> Optional[AgentConnection]:
        agent = self.get(agent_id)
        if not agent:
            return None
        update_data = payload.dict(exclude_unset=True, exclude_none=True)
        for field, value in update_data.items():
            setattr(agent, field, value)
        agent.last_heartbeat_at = datetime.utcnow()
        return agent

    def heartbeat(self, agent_id: UUID) -> Optional[AgentConnection]:
        agent = self.get(agent_id)
        if not agent:
            return None
        agent.last_heartbeat_at = datetime.utcnow()
        if agent.status == AgentStatus.DISCONNECTED:
            agent.status = AgentStatus.READY
        return agent

    def set_status(self, agent_id: UUID, status: AgentStatus) -> Optional[AgentConnection]:
        agent = self.get(agent_id)
        if not agent:
            return None
        agent.status = status
        agent.last_heartbeat_at = datetime.utcnow()
        return agent

    def ready_agents(self) -> Iterable[AgentConnection]:
        return [agent for agent in self._agents.values() if agent.status == AgentStatus.READY]


class IntelligenceStore:
    """Caches generated vulnerability intelligence per scan."""

    def __init__(self) -> None:
        self._intelligence: Dict[UUID, VulnerabilityIntelligence] = {}

    def get(self, scan_id: UUID) -> Optional[VulnerabilityIntelligence]:
        return self._intelligence.get(scan_id)

    def store(self, scan_id: UUID, intelligence: VulnerabilityIntelligence) -> VulnerabilityIntelligence:
        self._intelligence[scan_id] = intelligence
        return intelligence
