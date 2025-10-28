"""Pydantic data models for the MCP server API."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator

from .config import DEFAULT_REPORT_SECTIONS, DEFAULT_THRESHOLDS, ScanStatus, VulnerabilityClass


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
