from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class SecurityEvent:
    id: str
    timestamp: datetime
    session_id: str
    tool_name: str
    arguments: dict
    result: Optional[str]
    risk_score: int                     # 0–100
    severity: Severity
    anomaly_detected: bool
    pattern_matched: Optional[str]      # e.g. "prompt_injection"
    threat_name: Optional[str]          # friendly name
    action_taken: PolicyAction
    impact: str
    handled_by: str                     # description of who/what handled it

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "result_preview": (self.result or "")[:300],
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "anomaly_detected": self.anomaly_detected,
            "pattern_matched": self.pattern_matched,
            "threat_name": self.threat_name,
            "action_taken": self.action_taken.value,
            "impact": self.impact,
            "handled_by": self.handled_by,
        }


@dataclass
class SessionInfo:
    session_id: str
    threat_scenario: Optional[str]
    started_at: datetime
    last_activity: datetime
    risk_score: int = 0
    tool_call_count: int = 0
    blocked_count: int = 0
    anomaly_count: int = 0
    status: str = "active"             # active | completed | blocked

    @property
    def severity(self) -> Severity:
        if self.risk_score >= 80:
            return Severity.CRITICAL
        if self.risk_score >= 60:
            return Severity.HIGH
        if self.risk_score >= 35:
            return Severity.MEDIUM
        return Severity.LOW

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "threat_scenario": self.threat_scenario,
            "started_at": self.started_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "tool_call_count": self.tool_call_count,
            "blocked_count": self.blocked_count,
            "anomaly_count": self.anomaly_count,
            "status": self.status,
        }


@dataclass
class MCPServerInfo:
    id: str
    name: str
    url: str
    status: str                        # online | offline | shadow
    registered: bool
    risk_level: Severity
    tool_count: int
    last_seen: Optional[str]
    total_calls: int = 0
    blocked_calls: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "status": self.status,
            "registered": self.registered,
            "risk_level": self.risk_level.value,
            "tool_count": self.tool_count,
            "last_seen": self.last_seen,
            "total_calls": self.total_calls,
            "blocked_calls": self.blocked_calls,
        }


@dataclass
class PolicyConfig:
    tool_name: str
    action: PolicyAction
    description: str

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "action": self.action.value,
            "description": self.description,
        }


@dataclass
class CircuitBreaker:
    session_id: str
    state: CircuitState = CircuitState.CLOSED
    threshold: int = 4
    consecutive_risky: int = 0
    tripped_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "threshold": self.threshold,
            "consecutive_risky": self.consecutive_risky,
            "tripped_at": self.tripped_at.isoformat() if self.tripped_at else None,
        }
