"""
SecurityAnalyzer — anomaly detection, risk scoring, behavioral baselining.
"""
from __future__ import annotations
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .models import Severity

# ── Tool risk weights (0–100) ──────────────────────────────────────────────────
TOOL_RISK = {
    "exfiltrate_data":          95,
    "execute_admin_action":     90,
    "fetch_url":                75,
    "escalate_oauth_scope":     80,
    "request_permission":       70,
    "access_secret":            65,
    "reset_rate_limit":         60,
    "register_agent":           55,
    "query_employees":          50,
    "query_unregistered_services": 45,
    "install_mcp_package":      40,
    "get_user_profile":         35,
    "submit_expense":           30,
    "authenticate_user":        20,
    "check_rate_limit":         10,
    "list_installed_tools":     15,
    "search_records":           20,
    "get_api_call_stats":       10,
    "read_document":            10,
}

# ── Known attack patterns ──────────────────────────────────────────────────────
ATTACK_PATTERNS = {
    "prompt_injection": {
        "sequence":    ["read_document", "query_employees", "exfiltrate_data"],
        "description": "Prompt Injection via tool response",
        "severity":    Severity.CRITICAL,
    },
    "ssrf": {
        "tool":        "fetch_url",
        "url_regex":   r"169\.254|10\.|192\.168\.|127\.|localhost|\.internal",
        "description": "Server-Side Request Forgery (SSRF)",
        "severity":    Severity.CRITICAL,
    },
    "data_exfiltration": {
        "sequence":    ["query_employees", "exfiltrate_data"],
        "description": "Silent PII Data Exfiltration",
        "severity":    Severity.HIGH,
    },
    "privilege_escalation": {
        "sequence":    ["request_permission", "access_secret"],
        "description": "Progressive Privilege Escalation",
        "severity":    Severity.HIGH,
    },
    "confused_deputy": {
        "tool":        "execute_admin_action",
        "description": "Confused Deputy Attack",
        "severity":    Severity.HIGH,
    },
    "auth_abuse": {
        "sequence":    ["authenticate_user", "escalate_oauth_scope"],
        "description": "OAuth Scope Abuse",
        "severity":    Severity.HIGH,
    },
    "cross_tenant": {
        "tool":        "get_user_profile",
        "description": "Cross-Tenant IDOR Access",
        "severity":    Severity.HIGH,
    },
    "supply_chain": {
        "tool":        "install_mcp_package",
        "pkg_regex":   r"postgress|fi1e|memery|br0wser|glt|postres",
        "description": "Supply Chain Typosquatting Attack",
        "severity":    Severity.HIGH,
    },
    "resource_exhaustion": {
        "tool":            "search_records",
        "min_calls":       4,
        "description":     "Runaway Agent / Resource Exhaustion",
        "severity":        Severity.MEDIUM,
    },
    "business_logic_bypass": {
        "tool":        "submit_expense",
        "arg_key":     "approver_bypass",
        "arg_value":   True,
        "description": "Approval Workflow Bypass",
        "severity":    Severity.HIGH,
    },
    "rate_limit_reset": {
        "tool":        "reset_rate_limit",
        "description": "Unauthorized Rate Limit Reset",
        "severity":    Severity.MEDIUM,
    },
    "shadow_agent_trust": {
        "tool":        "register_agent",
        "arg_key":     "auto_trust",
        "arg_value":   True,
        "description": "Shadow Agent Auto-Trust Registration",
        "severity":    Severity.MEDIUM,
    },
    "pii_access": {
        "tool":    "query_employees",
        "arg_key": "include_pii",
        "arg_value": True,
        "description": "Unauthorized PII Data Access",
        "severity":    Severity.HIGH,
    },
}

# ── Impact descriptions per tool ───────────────────────────────────────────────
TOOL_IMPACT = {
    "exfiltrate_data":          "Employee PII (SSNs, salaries) being sent to external endpoint",
    "fetch_url":                "Internal network / cloud metadata accessible via SSRF",
    "execute_admin_action":     "Administrative action executed without human authorization",
    "escalate_oauth_scope":     "Session token scope elevated without user re-consent",
    "request_permission":       "Permission escalated automatically without human review",
    "access_secret":            "Privileged secret (API key / DB password) exposed",
    "reset_rate_limit":         "Rate limit protection bypassed — DoS mitigation removed",
    "register_agent":           "Unvetted MCP agent registered with system-level trust",
    "query_employees":          "Employee records queried — PII exposure risk",
    "install_mcp_package":      "External MCP package installed — supply chain risk",
    "submit_expense":           "Financial transaction submitted — potential fraud",
    "query_unregistered_services": "Shadow MCP servers discovered on internal network",
    "get_user_profile":         "User profile accessed — potential cross-tenant IDOR",
}


@dataclass
class AnomalyResult:
    risk_score: int
    severity: Severity
    anomaly_detected: bool
    pattern_matched: Optional[str]
    threat_name: Optional[str]
    impact: str


class SecurityAnalyzer:
    def __init__(self) -> None:
        # Per-session call history: session_id → deque of tool names
        self._call_history: dict[str, deque] = {}
        # Per-session tool call counts
        self._call_counts: dict[str, dict[str, int]] = {}

    def analyze(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict,
        result: str,
    ) -> AnomalyResult:
        # Update call history
        if session_id not in self._call_history:
            self._call_history[session_id] = deque(maxlen=20)
            self._call_counts[session_id] = {}
        history = self._call_history[session_id]
        history.append(tool_name)
        counts = self._call_counts[session_id]
        counts[tool_name] = counts.get(tool_name, 0) + 1

        base_risk = TOOL_RISK.get(tool_name, 20)
        pattern, threat_name = self._match_pattern(session_id, tool_name, arguments, counts)
        risk_score = self._calculate_risk(base_risk, tool_name, arguments, pattern)
        severity = self._score_to_severity(risk_score)
        impact = self._get_impact(tool_name, arguments, pattern)

        return AnomalyResult(
            risk_score=risk_score,
            severity=severity,
            anomaly_detected=pattern is not None,
            pattern_matched=pattern,
            threat_name=threat_name,
            impact=impact,
        )

    def _match_pattern(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict,
        counts: dict,
    ) -> tuple[Optional[str], Optional[str]]:
        history = list(self._call_history[session_id])

        for pat_id, pat in ATTACK_PATTERNS.items():
            # Sequence-based patterns
            if "sequence" in pat:
                seq = pat["sequence"]
                if len(history) >= len(seq) and history[-len(seq):] == seq:
                    return pat_id, pat["description"]
            # Single-tool patterns with arg matching
            if pat.get("tool") == tool_name:
                if "url_regex" in pat:
                    url = arguments.get("url", "")
                    if re.search(pat["url_regex"], url, re.IGNORECASE):
                        return pat_id, pat["description"]
                if "pkg_regex" in pat:
                    pkg = arguments.get("package_name", "")
                    if re.search(pat["pkg_regex"], pkg, re.IGNORECASE):
                        return pat_id, pat["description"]
                if "arg_key" in pat:
                    if arguments.get(pat["arg_key"]) == pat["arg_value"]:
                        return pat_id, pat["description"]
                if "min_calls" in pat:
                    if counts.get(tool_name, 0) >= pat["min_calls"]:
                        return pat_id, pat["description"]
                # Plain tool match (no arg condition)
                if not any(k in pat for k in ("url_regex", "pkg_regex", "arg_key", "min_calls")):
                    return pat_id, pat["description"]

        return None, None

    def _calculate_risk(
        self,
        base: int,
        tool_name: str,
        arguments: dict,
        pattern: Optional[str],
    ) -> int:
        score = base
        # Argument-based risk boosters
        if arguments.get("include_pii"):
            score = min(100, score + 25)
        if arguments.get("approver_bypass"):
            score = min(100, score + 30)
        if arguments.get("auto_trust"):
            score = min(100, score + 20)
        if arguments.get("encoding") in ("base64", "hex"):
            score = min(100, score + 15)
        if tool_name == "fetch_url":
            url = arguments.get("url", "")
            if re.search(r"169\.254|metadata", url, re.IGNORECASE):
                score = 98
        if tool_name == "access_secret":
            key = arguments.get("key_name", "")
            if "MASTER" in key or "PASSWORD" in key or "SECRET" in key:
                score = min(100, score + 25)
        if pattern:
            score = min(100, score + 10)
        return score

    @staticmethod
    def _score_to_severity(score: int) -> Severity:
        if score >= 80:
            return Severity.CRITICAL
        if score >= 60:
            return Severity.HIGH
        if score >= 35:
            return Severity.MEDIUM
        return Severity.LOW

    def _get_impact(self, tool_name: str, arguments: dict, pattern: Optional[str]) -> str:
        if pattern and pattern in ATTACK_PATTERNS:
            base = ATTACK_PATTERNS[pattern]["description"]
            extra = TOOL_IMPACT.get(tool_name, "")
            if extra:
                return f"{base} — {extra}"
            return base
        return TOOL_IMPACT.get(tool_name, f"Tool '{tool_name}' invoked")

    def reset_session(self, session_id: str) -> None:
        self._call_history.pop(session_id, None)
        self._call_counts.pop(session_id, None)
