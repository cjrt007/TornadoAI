"""Pydantic data models for the MCP server API."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator

from .config import (
    DEFAULT_REPORT_SECTIONS,
    DEFAULT_THRESHOLDS,
    AgentRole,
    AgentStatus,
    RiskLevel,
    ScanStatus,
    VulnerabilityClass,
)


class Thresholds(BaseModel):
    """Threshold configuration for a scan."""

    max_open_ports: float = Field(
        DEFAULT_THRESHOLDS["max_open_ports"],
        description="Maximum number of open ports before marking scan as high risk.",
    )
    max_critical_findings: float = Field(
        DEFAULT_THRESHOLDS["max_critical_findings"],
        description="Maximum count of critical findings before alerting.",
    )
    max_high_findings: float = Field(
        DEFAULT_THRESHOLDS["max_high_findings"],
        description="Maximum number of high severity issues permitted before aborting.",
    )


class ScanTask(BaseModel):
    """Represents an individual step executed during a scan."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    tool: Optional[str] = Field(
        default=None,
        description="Identifier of the security tool responsible for the task.",
    )
    parameters: Dict[str, str] = Field(default_factory=dict)
    required_vulnerabilities: List[VulnerabilityClass] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ScanBase(BaseModel):
    """Common fields required to create or update a scan."""

    name: str
    target: str = Field(description="Target host, URL or bundle identifier under test.")
    vulnerability_classes: List[VulnerabilityClass] = Field(
        default_factory=list,
        description="Vulnerability classes to focus on during the assessment.",
    )
    duration: timedelta = Field(
        default=timedelta(hours=1),
        description="Maximum allotted time for the scan."
        " Use ISO 8601 duration strings or seconds when invoking the API.",
    )
    thresholds: Thresholds = Field(default_factory=Thresholds)
    tool_overrides: Dict[str, Dict[str, str]] = Field(
        default_factory=dict,
        description="Fine grained configuration overrides per tool.",
    )

    class Config:
        json_encoders = {timedelta: lambda value: value.total_seconds()}

    @validator("duration", pre=True)
    def _coerce_duration(cls, value: timedelta | int | float) -> timedelta:
        """Allow callers to provide duration in seconds."""

        if isinstance(value, timedelta):
            return value
        return timedelta(seconds=float(value))


class ScanCreate(ScanBase):
    """Request body for creating a new scan."""

    tasks: List[ScanTask] = Field(
        default_factory=list,
        description="Initial set of tasks to run. Additional tasks can be added dynamically.",
    )


class ScanUpdate(BaseModel):
    """Request body for partial scan updates."""

    name: Optional[str] = None
    target: Optional[str] = None
    vulnerability_classes: Optional[List[VulnerabilityClass]] = None
    duration: Optional[timedelta | float | int] = None
    thresholds: Optional[Thresholds] = None
    tool_overrides: Optional[Dict[str, Dict[str, str]]] = None

    @validator("duration", pre=True)
    def _coerce_duration(cls, value: timedelta | float | int | None) -> Optional[timedelta]:
        if value is None or isinstance(value, timedelta):
            return value
        return timedelta(seconds=float(value))


class Scan(ScanBase):
    """Full representation of a scan job."""

    id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = Field(default=ScanStatus.DRAFT)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tasks: List[ScanTask] = Field(default_factory=list)


class ReportSection(BaseModel):
    """Represents a single section of a custom report."""

    title: str
    content: str = Field(default="", description="Markdown content for the section.")
    include: bool = Field(default=True)


class ReportBase(BaseModel):
    """Fields shared by report requests and responses."""

    scan_id: UUID
    sections: List[ReportSection] = Field(
        default_factory=lambda: [
            ReportSection(title=section_name)
            for section_name in DEFAULT_REPORT_SECTIONS
        ]
    )


class ReportCreate(ReportBase):
    """Request model for creating reports."""

    title: str = Field(default="Security Assessment Report")


class ReportUpdate(BaseModel):
    """Allows updates to an existing report."""

    title: Optional[str] = None
    sections: Optional[List[ReportSection]] = None


class Report(ReportBase):
    """Stored representation of a report."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ToolDescriptor(BaseModel):
    """Metadata about a security tool integrated with the platform."""

    name: str
    category: str
    description: str
    command: str
    supports_real_time_control: bool = Field(default=True)
    documentation: Optional[str] = None


class AgentBase(BaseModel):
    """Fields shared by agent registration and stored representations."""

    name: str
    provider: str = Field(
        description="Large language model provider, framework, or agent implementation identifier.",
    )
    role: AgentRole
    capabilities: List[str] = Field(
        default_factory=list,
        description="Semantic capabilities advertised by the agent (e.g. reconnaissance, exploitation).",
    )
    protocol: str = Field(
        default="fastmcp",
        description="Transport protocol the agent is listening on for orchestration commands.",
    )
    metadata: Dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary metadata such as region, environment, or tuning notes.",
    )


class AgentRegistration(AgentBase):
    """Payload used when an agent establishes a session with TornadoAI."""

    heartbeat_interval_seconds: Optional[int] = Field(
        default=60,
        description="How often the agent expects to report heartbeats.",
    )


class AgentUpdate(BaseModel):
    """Partial update payload for maintaining agent state."""

    name: Optional[str] = None
    capabilities: Optional[List[str]] = None
    protocol: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None
    status: Optional[AgentStatus] = None
    heartbeat_interval_seconds: Optional[int] = None


class AgentConnection(AgentBase):
    """Runtime view of a connected agent."""

    id: UUID = Field(default_factory=uuid4)
    status: AgentStatus = Field(default=AgentStatus.READY)
    heartbeat_interval_seconds: int = Field(default=60)
    connected_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat_at: datetime = Field(default_factory=datetime.utcnow)


class OrchestrationRequest(BaseModel):
    """Additional context supplied when requesting an autonomous execution plan."""

    threat_level: RiskLevel = Field(default=RiskLevel.MODERATE)
    observed_vulnerabilities: List[VulnerabilityClass] = Field(
        default_factory=list,
        description="Recently identified vulnerability classes that should influence prioritization.",
    )
    preferred_agents: List[UUID] = Field(
        default_factory=list,
        description="Agent identifiers to prioritize when building the execution plan.",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Free-form hints from operators or upstream systems.",
    )


class AgentAssignment(BaseModel):
    """Mapping between an agent and the concrete tasks it should perform."""

    agent_id: UUID
    agent_name: str
    role: AgentRole
    tasks: List[ScanTask] = Field(default_factory=list)
    notes: Optional[str] = Field(default=None)


class StrategyDecision(BaseModel):
    """High-level reasoning behind the generated execution plan."""

    summary: str
    rationale: List[str] = Field(default_factory=list)
    selected_agents: List[UUID] = Field(default_factory=list)
    toolset: List[str] = Field(default_factory=list)
    adaptive_responses: List[str] = Field(default_factory=list)


class VulnerabilityInsight(BaseModel):
    """Structured insight produced by the intelligence engine."""

    vulnerability_class: VulnerabilityClass
    likelihood: float = Field(
        ge=0.0,
        le=1.0,
        description="Estimated likelihood (0-1) that the vulnerability will be observed.",
    )
    impact: float = Field(
        ge=0.0,
        le=1.0,
        description="Estimated impact (0-1) should exploitation occur.",
    )
    description: str
    recommended_actions: List[str] = Field(default_factory=list)


class VulnerabilityCard(BaseModel):
    """Visual card representation of a vulnerability insight for reporting."""

    identifier: str
    title: str
    severity: RiskLevel
    risk_score: float = Field(ge=0.0)
    summary: str
    evidence: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)


class VulnerabilityIntelligence(BaseModel):
    """Aggregate intelligence package produced for a scan."""

    insights: List[VulnerabilityInsight] = Field(default_factory=list)
    cards: List[VulnerabilityCard] = Field(default_factory=list)
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    risk_score: float = Field(
        ge=0.0,
        description="Composite risk score derived from likelihood and impact heuristics.",
    )
    narrative: str = Field(default="")


class ExecutionPlan(BaseModel):
    """Execution blueprint returned to orchestrate autonomous assessments."""

    plan_id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    decision: StrategyDecision
    assignments: List[AgentAssignment] = Field(default_factory=list)
    intelligence: VulnerabilityIntelligence
