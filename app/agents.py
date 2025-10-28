"""Multi-agent orchestration and decision-making utilities."""
from __future__ import annotations

from collections import defaultdict
from itertools import cycle
from typing import Dict, Iterable, List, Tuple
from uuid import UUID

from .config import AgentRole, AgentStatus, RiskLevel, VulnerabilityClass
from .models import (
    AgentAssignment,
    AgentConnection,
    ExecutionPlan,
    OrchestrationRequest,
    Scan,
    ScanTask,
    StrategyDecision,
    VulnerabilityCard,
    VulnerabilityInsight,
    VulnerabilityIntelligence,
)
from .store import AgentStore, IntelligenceStore, ScanStore
from .tooling import tool_lookup


_DEFAULT_TOOL_FALLBACK = ["nmap", "nuclei"]

_VULNERABILITY_TOOL_MAP: Dict[VulnerabilityClass, List[str]] = {
    VulnerabilityClass.A03_INJECTION: ["sqlmap", "nuclei", "ffuf"],
    VulnerabilityClass.A01_BROKEN_ACCESS_CONTROL: ["nuclei", "burpsuite"],
    VulnerabilityClass.A05_SECURITY_MISCONFIG: ["nmap", "dirb"],
    VulnerabilityClass.A07_IDENT_AND_AUTHN_FAILS: ["nuclei", "whatweb"],
    VulnerabilityClass.A10_SERVER_SIDE_REQUEST_FORGERY: ["nuclei", "ffuf"],
    VulnerabilityClass.M3_INSECURE_COMMUNICATION: ["whatweb", "nmap"],
    VulnerabilityClass.M4_INSECURE_AUTHENTICATION: ["nuclei", "objection"],
    VulnerabilityClass.M6_INSECURE_AUTHORIZATION: ["nuclei", "burpsuite"],
    VulnerabilityClass.M9_REVERSE_ENGINEERING: ["jadx", "apktool"],
    VulnerabilityClass.CWE_79_XSS: ["nuclei", "ffuf"],
    VulnerabilityClass.CWE_89_SQL_INJECTION: ["sqlmap", "nuclei"],
    VulnerabilityClass.CWE_787_OUT_OF_BOUNDS_WRITE: ["MobSF", "frida"],
}

_BASE_LIKELIHOOD: Dict[VulnerabilityClass, float] = defaultdict(
    lambda: 0.45,
    {
        VulnerabilityClass.A03_INJECTION: 0.65,
        VulnerabilityClass.A05_SECURITY_MISCONFIG: 0.6,
        VulnerabilityClass.CWE_352_CSRF: 0.4,
        VulnerabilityClass.CWE_89_SQL_INJECTION: 0.7,
        VulnerabilityClass.M3_INSECURE_COMMUNICATION: 0.55,
    },
)

_BASE_IMPACT: Dict[VulnerabilityClass, float] = defaultdict(
    lambda: 0.5,
    {
        VulnerabilityClass.A01_BROKEN_ACCESS_CONTROL: 0.75,
        VulnerabilityClass.A03_INJECTION: 0.8,
        VulnerabilityClass.A10_SERVER_SIDE_REQUEST_FORGERY: 0.7,
        VulnerabilityClass.CWE_79_XSS: 0.6,
        VulnerabilityClass.CWE_89_SQL_INJECTION: 0.85,
        VulnerabilityClass.CWE_787_OUT_OF_BOUNDS_WRITE: 0.9,
    },
)


class DecisionEngine:
    """Encapsulates heuristics for building autonomous execution plans."""

    def __init__(self, agent_store: AgentStore) -> None:
        self._agent_store = agent_store
        self._tool_catalog = tool_lookup()

    def available_agents(self, context: OrchestrationRequest) -> List[AgentConnection]:
        """Return agents sorted by operator preferences and readiness."""

        agents = list(self._agent_store.ready_agents())
        if not agents:
            return []
        if context.preferred_agents:
            prioritized: List[AgentConnection] = []
            remainder: List[AgentConnection] = []
            preferred_set = set(context.preferred_agents)
            for agent in agents:
                (prioritized if agent.id in preferred_set else remainder).append(agent)
            return prioritized + remainder
        return agents

    def generate_plan(
        self,
        scan: Scan,
        context: OrchestrationRequest,
        agents: List[AgentConnection],
    ) -> Tuple[StrategyDecision, List[AgentAssignment], VulnerabilityIntelligence]:
        tool_mapping = self._build_tool_mapping(scan, context)
        assignments = self._build_assignments(scan, agents, tool_mapping)
        decision = self._build_strategy(scan, context, agents, assignments, tool_mapping)
        intelligence = self._build_intelligence(scan, context, tool_mapping)
        return decision, assignments, intelligence

    def _build_tool_mapping(
        self, scan: Scan, context: OrchestrationRequest
    ) -> Dict[VulnerabilityClass, List[str]]:
        classes = list(scan.vulnerability_classes)
        for observed in context.observed_vulnerabilities:
            if observed not in classes:
                classes.append(observed)
        if not classes:
            classes = [VulnerabilityClass.A05_SECURITY_MISCONFIG]
        mapping: Dict[VulnerabilityClass, List[str]] = {}
        for vuln_class in classes:
            mapping[vuln_class] = _VULNERABILITY_TOOL_MAP.get(vuln_class, _DEFAULT_TOOL_FALLBACK)
        return mapping

    def _build_assignments(
        self,
        scan: Scan,
        agents: List[AgentConnection],
        tool_mapping: Dict[VulnerabilityClass, List[str]],
    ) -> List[AgentAssignment]:
        if not agents:
            return []
        assignments: Dict[UUID, List[ScanTask]] = defaultdict(list)
        agent_rotation = cycle(agents)
        for vuln_class, tools in tool_mapping.items():
            for tool in tools:
                agent = next(agent_rotation)
                descriptor = self._tool_catalog.get(tool)
                task_name = f"{tool.upper()} assessment"
                description = descriptor.description if descriptor else f"Run {tool} against target"
                parameters: Dict[str, str] = {"target": scan.target}
                task = ScanTask(
                    name=task_name,
                    description=f"{description} for {self._format_vulnerability(vuln_class)}",
                    tool=descriptor.name if descriptor else tool,
                    parameters=parameters,
                    required_vulnerabilities=[vuln_class],
                )
                assignments[agent.id].append(task)
        result: List[AgentAssignment] = []
        for agent in agents:
            tasks = assignments.get(agent.id, [])
            if not tasks:
                continue
            result.append(
                AgentAssignment(
                    agent_id=agent.id,
                    agent_name=agent.name,
                    role=agent.role,
                    tasks=tasks,
                    notes=self._build_assignment_notes(agent, tasks),
                )
            )
        return result

    def _build_strategy(
        self,
        scan: Scan,
        context: OrchestrationRequest,
        agents: List[AgentConnection],
        assignments: List[AgentAssignment],
        tool_mapping: Dict[VulnerabilityClass, List[str]],
    ) -> StrategyDecision:
        toolset = sorted({task.tool for assignment in assignments for task in assignment.tasks})
        focus = ", ".join(self._format_vulnerability(v) for v in tool_mapping.keys())
        summary = (
            f"{context.threat_level.value.title()} threat posture focusing on {focus or 'baseline hardening'} "
            f"against target {scan.target}."
        )
        rationale = [
            "Prioritized vulnerability classes requested in the scan configuration.",
            "Balanced coverage across connected agents to maximize concurrency.",
        ]
        if context.observed_vulnerabilities:
            rationale.append(
                "Incorporated recently observed findings to adapt the execution plan in real time."
            )
        adaptive_responses: List[str] = []
        for observed in context.observed_vulnerabilities:
            adaptive_responses.append(
                f"Elevated priority for {self._format_vulnerability(observed)} based on live telemetry."
            )
        if context.notes:
            rationale.append(f"Operator notes: {context.notes}")
        return StrategyDecision(
            summary=summary,
            rationale=rationale,
            selected_agents=[agent.id for agent in agents],
            toolset=toolset,
            adaptive_responses=adaptive_responses,
        )

    def _build_intelligence(
        self,
        scan: Scan,
        context: OrchestrationRequest,
        tool_mapping: Dict[VulnerabilityClass, List[str]],
    ) -> VulnerabilityIntelligence:
        insights: List[VulnerabilityInsight] = []
        cards: List[VulnerabilityCard] = []
        scores: List[float] = []
        for vuln_class, tools in tool_mapping.items():
            likelihood = _BASE_LIKELIHOOD[vuln_class]
            if context.threat_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                likelihood += 0.1
            if vuln_class in context.observed_vulnerabilities:
                likelihood += 0.15
            likelihood = min(likelihood, 1.0)

            impact = _BASE_IMPACT[vuln_class]
            if context.threat_level == RiskLevel.CRITICAL:
                impact += 0.1
            impact = min(impact, 1.0)

            risk_score = round((likelihood * 0.6 + impact * 0.4) * 10, 2)
            scores.append(risk_score)
            severity = self._score_to_risk_level(risk_score)
            description = (
                f"Automated analysis anticipates {self._format_vulnerability(vuln_class)} may be present on "
                f"target {scan.target}."
            )
            actions = [f"Execute {tool} task" for tool in tools]
            insights.append(
                VulnerabilityInsight(
                    vulnerability_class=vuln_class,
                    likelihood=round(likelihood, 2),
                    impact=round(impact, 2),
                    description=description,
                    recommended_actions=actions,
                )
            )
            cards.append(
                VulnerabilityCard(
                    identifier=vuln_class.value,
                    title=self._format_vulnerability(vuln_class),
                    severity=severity,
                    risk_score=risk_score,
                    summary=description,
                    recommendations=actions,
                )
            )
        composite_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        risk_level = self._score_to_risk_level(composite_score)
        narrative = (
            "Risk score synthesizes likelihood and impact estimates derived from vulnerability focus, "
            "recent telemetry, and scan thresholds."
        )
        return VulnerabilityIntelligence(
            insights=insights,
            cards=cards,
            risk_level=risk_level,
            risk_score=composite_score,
            narrative=narrative,
        )

    def _build_assignment_notes(self, agent: AgentConnection, tasks: Iterable[ScanTask]) -> str:
        task_list = list(tasks)
        task_names = ", ".join(task.tool for task in task_list)
        return (
            f"Assigned {len(task_list)} tasks to {agent.provider} {agent.role.value} agent focusing on {task_names}."
        )

    def _format_vulnerability(self, vuln: VulnerabilityClass) -> str:
        label = vuln.value.replace("_", " ").title()
        return label.replace("Owasp", "OWASP").replace("Cwe", "CWE")

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        if score >= 7.5:
            return RiskLevel.CRITICAL
        if score >= 5.5:
            return RiskLevel.HIGH
        if score >= 3.5:
            return RiskLevel.MODERATE
        return RiskLevel.LOW


class MultiAgentOrchestrator:
    """Coordinates agent assignment, decisioning, and intelligence capture."""

    def __init__(
        self,
        scan_store: ScanStore,
        agent_store: AgentStore,
        intelligence_store: IntelligenceStore,
    ) -> None:
        self._scan_store = scan_store
        self._agent_store = agent_store
        self._intelligence_store = intelligence_store
        self._engine = DecisionEngine(agent_store)

    def plan(self, scan: Scan, context: OrchestrationRequest) -> ExecutionPlan:
        agents = self._engine.available_agents(context)
        if not agents:
            raise ValueError("No ready agents are available for orchestration.")
        decision, assignments, intelligence = self._engine.generate_plan(scan, context, agents)
        for assignment in assignments:
            for task in assignment.tasks:
                self._scan_store.add_task(scan.id, task)
            self._agent_store.set_status(assignment.agent_id, AgentStatus.BUSY)
        self._intelligence_store.store(scan.id, intelligence)
        return ExecutionPlan(
            scan_id=scan.id,
            decision=decision,
            assignments=assignments,
            intelligence=intelligence,
        )
