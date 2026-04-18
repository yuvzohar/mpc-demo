"""
SecurityEnforcer — policy engine, per-session rate limiting, circuit breakers.
"""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .models import PolicyAction, PolicyConfig, CircuitBreaker, CircuitState, Severity

# ── Default policies ────────────────────────────────────────────────────────────
DEFAULT_POLICIES: dict[str, PolicyAction] = {
    "exfiltrate_data":              PolicyAction.BLOCK,
    "execute_admin_action":         PolicyAction.WARN,
    "fetch_url":                    PolicyAction.WARN,
    "escalate_oauth_scope":         PolicyAction.WARN,
    "request_permission":           PolicyAction.WARN,
    "access_secret":                PolicyAction.ALLOW,
    "reset_rate_limit":             PolicyAction.WARN,
    "register_agent":               PolicyAction.ALLOW,
    "query_employees":              PolicyAction.ALLOW,
    "install_mcp_package":          PolicyAction.ALLOW,
    "submit_expense":               PolicyAction.ALLOW,
    "query_unregistered_services":  PolicyAction.ALLOW,
    "get_user_profile":             PolicyAction.ALLOW,
    "authenticate_user":            PolicyAction.ALLOW,
    "check_rate_limit":             PolicyAction.ALLOW,
    "list_installed_tools":         PolicyAction.ALLOW,
    "search_records":               PolicyAction.ALLOW,
    "get_api_call_stats":           PolicyAction.ALLOW,
    "read_document":                PolicyAction.ALLOW,
}

POLICY_DESCRIPTIONS: dict[str, str] = {
    "exfiltrate_data":              "Outbound data transmission — always block",
    "execute_admin_action":         "Privileged admin operations — require audit",
    "fetch_url":                    "Outbound HTTP — SSRF risk",
    "escalate_oauth_scope":         "OAuth scope elevation — warn on use",
    "request_permission":           "Permission escalation — warn on use",
    "access_secret":                "Secret vault access",
    "reset_rate_limit":             "Rate limit controls — warn on unauthorized reset",
    "register_agent":               "Agent registration",
    "query_employees":              "Employee record access",
    "install_mcp_package":          "Package installation — supply chain risk",
    "submit_expense":               "Financial transactions",
    "query_unregistered_services":  "Shadow service discovery",
    "get_user_profile":             "User profile access — IDOR risk",
    "authenticate_user":            "Authentication",
    "check_rate_limit":             "Rate limit status check",
    "list_installed_tools":         "Tool inventory",
    "search_records":               "Record search",
    "get_api_call_stats":           "Usage statistics",
    "read_document":                "Document read",
}

# ── Rate limit settings (calls per 60-second window per session) ────────────────
RATE_LIMITS: dict[str, int] = {
    "exfiltrate_data":  2,
    "fetch_url":        5,
    "query_employees":  10,
    "search_records":   15,
    "access_secret":    5,
    "submit_expense":   5,
    "_default":         30,
}

CIRCUIT_BREAKER_THRESHOLD = 4   # consecutive risky calls (score ≥ 60) trips the breaker
CIRCUIT_RESET_SECONDS    = 30   # auto-reset after this many seconds


@dataclass
class EnforcerDecision:
    allowed: bool
    action: PolicyAction
    reason: str


class SecurityEnforcer:
    def __init__(self) -> None:
        self._policies: dict[str, PolicyAction] = dict(DEFAULT_POLICIES)
        # Rate limiting: session → tool → list of timestamps
        self._call_timestamps: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        # Circuit breakers per session
        self._circuits: dict[str, CircuitBreaker] = {}

    # ── Decision ────────────────────────────────────────────────────────────────

    def check(self, session_id: str, tool_name: str, risk_score: int) -> EnforcerDecision:
        # 1. Circuit breaker check (overrides everything)
        cb_decision = self._check_circuit(session_id)
        if cb_decision is not None:
            return cb_decision

        # 2. Policy check
        action = self._policies.get(tool_name, PolicyAction.ALLOW)
        if action == PolicyAction.BLOCK:
            return EnforcerDecision(
                allowed=False,
                action=PolicyAction.BLOCK,
                reason=f"Policy: tool '{tool_name}' is BLOCKED",
            )

        # 3. Rate limit check
        rl_decision = self._check_rate_limit(session_id, tool_name)
        if rl_decision is not None:
            return rl_decision

        # 4. Update circuit breaker state
        self._update_circuit(session_id, risk_score)

        return EnforcerDecision(
            allowed=True,
            action=action,
            reason=f"Policy: {action.value}" if action != PolicyAction.ALLOW else "Allowed",
        )

    # ── Rate limiting ────────────────────────────────────────────────────────────

    def _check_rate_limit(self, session_id: str, tool_name: str) -> Optional[EnforcerDecision]:
        limit = RATE_LIMITS.get(tool_name, RATE_LIMITS["_default"])
        now = time.time()
        window_start = now - 60.0

        timestamps = self._call_timestamps[session_id][tool_name]
        # Evict old entries
        self._call_timestamps[session_id][tool_name] = [t for t in timestamps if t > window_start]
        current = len(self._call_timestamps[session_id][tool_name])

        if current >= limit:
            return EnforcerDecision(
                allowed=False,
                action=PolicyAction.BLOCK,
                reason=f"Rate limited: {current}/{limit} calls per 60s for '{tool_name}'",
            )
        self._call_timestamps[session_id][tool_name].append(now)
        return None

    # ── Circuit breaker ──────────────────────────────────────────────────────────

    def _check_circuit(self, session_id: str) -> Optional[EnforcerDecision]:
        cb = self._circuits.get(session_id)
        if cb is None:
            return None
        if cb.state == CircuitState.OPEN:
            age = (datetime.now() - cb.tripped_at).total_seconds() if cb.tripped_at else 999
            if age > CIRCUIT_RESET_SECONDS:
                cb.state = CircuitState.HALF_OPEN
                cb.consecutive_risky = 0
                return None
            return EnforcerDecision(
                allowed=False,
                action=PolicyAction.BLOCK,
                reason=f"Circuit breaker OPEN — session {session_id} tripped after "
                       f"{cb.threshold} consecutive high-risk calls",
            )
        return None

    def _update_circuit(self, session_id: str, risk_score: int) -> None:
        if session_id not in self._circuits:
            self._circuits[session_id] = CircuitBreaker(session_id=session_id)
        cb = self._circuits[session_id]
        if risk_score >= 60:
            cb.consecutive_risky += 1
        else:
            cb.consecutive_risky = max(0, cb.consecutive_risky - 1)

        if cb.consecutive_risky >= cb.threshold and cb.state == CircuitState.CLOSED:
            cb.state = CircuitState.OPEN
            cb.tripped_at = datetime.now()

        if cb.state == CircuitState.HALF_OPEN and risk_score < 60:
            cb.state = CircuitState.CLOSED

    # ── Policy management ────────────────────────────────────────────────────────

    def set_policy(self, tool_name: str, action: str) -> None:
        self._policies[tool_name] = PolicyAction(action)

    def get_all_policies(self) -> list[dict]:
        return [
            PolicyConfig(
                tool_name=t,
                action=self._policies.get(t, PolicyAction.ALLOW),
                description=POLICY_DESCRIPTIONS.get(t, ""),
            ).to_dict()
            for t in sorted(POLICY_DESCRIPTIONS.keys())
        ]

    def reset_circuit(self, session_id: str) -> None:
        if session_id in self._circuits:
            self._circuits[session_id].state = CircuitState.CLOSED
            self._circuits[session_id].consecutive_risky = 0

    def get_circuits(self) -> list[dict]:
        return [cb.to_dict() for cb in self._circuits.values()]

    def get_rate_limit_status(self, session_id: str) -> list[dict]:
        result = []
        now = time.time()
        window_start = now - 60.0
        for tool, limit in RATE_LIMITS.items():
            if tool == "_default":
                continue
            ts = self._call_timestamps[session_id].get(tool, [])
            current = sum(1 for t in ts if t > window_start)
            result.append({
                "tool": tool,
                "used": current,
                "limit": limit,
                "remaining": max(0, limit - current),
            })
        return result
