"""
MCPSecurityProxy — intercepts every MCP tool call, applies enforcement,
runs anomaly detection, and emits SecurityEvents to the dashboard.
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional

from mcp.types import Tool

from core.mcp_host import MCPHost
from .analyzer import SecurityAnalyzer
from .enforcer import SecurityEnforcer, EnforcerDecision
from .models import PolicyAction, SecurityEvent, Severity

EventCallback = Callable[[SecurityEvent], Awaitable[None]]


class MCPSecurityProxy:
    """
    Drop-in replacement for MCPHost that adds interception.
    Threat scenarios receive this instead of MCPHost — no code changes needed.
    """

    def __init__(
        self,
        real_host: MCPHost,
        analyzer: SecurityAnalyzer,
        enforcer: SecurityEnforcer,
        on_event: EventCallback,
    ) -> None:
        self._host = real_host
        self._analyzer = analyzer
        self._enforcer = enforcer
        self._on_event = on_event
        self._current_session: str = "default"

    def set_session(self, session_id: str) -> None:
        self._current_session = session_id

    # ── MCPHost interface (pass-through with interception) ─────────────────────

    def list_tools(self) -> list[Tool]:
        return self._host.list_tools()

    def tool_schemas_for_anthropic(self) -> list[dict]:
        return self._host.tool_schemas_for_anthropic()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        session_id = self._current_session

        # ── 1. Pre-analysis (score the call before execution) ──────────────────
        pre = self._analyzer.analyze(session_id, tool_name, arguments, "")
        risk_score = pre.risk_score

        # ── 2. Enforcement check ───────────────────────────────────────────────
        decision = self._enforcer.check(session_id, tool_name, risk_score)

        if not decision.allowed:
            result = json.dumps({
                "blocked": True,
                "reason": decision.reason,
                "tool": tool_name,
            })
            await self._emit(
                session_id, tool_name, arguments, result,
                risk_score, pre.severity, pre.anomaly_detected,
                pre.pattern_matched, pre.threat_name,
                decision.action, pre.impact,
                f"Blocked — {decision.reason}",
            )
            return result

        # ── 3. Execute real tool call ──────────────────────────────────────────
        try:
            result = await self._host.call_tool(tool_name, arguments)
        except Exception as exc:
            result = json.dumps({"error": str(exc)})

        # ── 4. Post-execution analysis (with actual result) ───────────────────
        post = self._analyzer.analyze(session_id, tool_name, arguments, result)

        handled = self._build_handled_message(decision, post.pattern_matched)

        await self._emit(
            session_id, tool_name, arguments, result,
            post.risk_score, post.severity, post.anomaly_detected,
            post.pattern_matched, post.threat_name,
            decision.action, post.impact, handled,
        )

        return result

    # ── Context manager (delegate to real host) ────────────────────────────────

    async def __aenter__(self) -> "MCPSecurityProxy":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    # ── Internals ──────────────────────────────────────────────────────────────

    async def _emit(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict,
        result: str,
        risk_score: int,
        severity: Severity,
        anomaly: bool,
        pattern: Optional[str],
        threat_name: Optional[str],
        action: PolicyAction,
        impact: str,
        handled: str,
    ) -> None:
        event = SecurityEvent(
            id=uuid.uuid4().hex[:12],
            timestamp=datetime.now(),
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            risk_score=risk_score,
            severity=severity,
            anomaly_detected=anomaly,
            pattern_matched=pattern,
            threat_name=threat_name,
            action_taken=action,
            impact=impact,
            handled_by=handled,
        )
        await self._on_event(event)

    @staticmethod
    def _build_handled_message(decision: EnforcerDecision, pattern: Optional[str]) -> str:
        if not decision.allowed:
            return f"🛡️  {decision.reason}"
        if decision.action == PolicyAction.WARN:
            msg = f"⚠️  Warning logged — {decision.reason}"
            if pattern:
                msg += f" (pattern: {pattern})"
            return msg
        return "✅  Allowed — policy: ALLOW"
