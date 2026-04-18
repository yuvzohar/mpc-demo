"""
DemoAgent — runs an agentic tool-use loop.

DEMO_MODE (default): scripted_steps drive the agent's decisions, but every
tool call is executed against the REAL MCP server so results are live data.

Real mode (DEMO_MODE=false): uses Anthropic claude-sonnet-4-6 to make actual
decisions; set ANTHROPIC_API_KEY in the environment.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Any

from .mcp_host import MCPHost


@dataclass
class ToolCall:
    tool_name: str
    arguments: dict
    result: str | None = None
    is_malicious: bool = False


@dataclass
class AgentTurn:
    thought: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    final_answer: str | None = None


class DemoAgent:
    def __init__(self, mcp_host: MCPHost, demo_mode: bool = True):
        self.mcp_host = mcp_host
        self.demo_mode = demo_mode
        self._client = None
        if not demo_mode:
            try:
                import anthropic
                api_key = os.getenv("ANTHROPIC_API_KEY")
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY not set; falling back to DEMO_MODE")
                self._client = anthropic.Anthropic(api_key=api_key)
            except Exception as exc:
                print(f"[yellow]Warning: {exc} — using DEMO_MODE[/yellow]")
                self.demo_mode = True

    async def run_scenario(
        self,
        system_prompt: str,
        user_message: str,
        scripted_steps: list[dict] | None = None,
        max_iterations: int = 15,
    ) -> list[AgentTurn]:
        if self.demo_mode:
            return await self._run_scripted(scripted_steps or [])
        return await self._run_real(system_prompt, user_message, max_iterations)

    # ── scripted mode ──────────────────────────────────────────────────────

    async def _run_scripted(self, steps: list[dict]) -> list[AgentTurn]:
        turns: list[AgentTurn] = []
        tool_results: dict[str, str] = {}

        for step in steps:
            thought = step.get("thought", "")
            final_answer = step.get("final_answer")
            raw_calls = step.get("tool_calls", [])

            executed_calls: list[ToolCall] = []
            for tc in raw_calls:
                tool_name = tc["tool"]
                # Resolve template placeholders from prior results
                args = self._resolve_args(tc.get("args", {}), tool_results)
                is_malicious = tc.get("is_malicious", False)
                try:
                    result = await self.mcp_host.call_tool(tool_name, args)
                except Exception as exc:
                    result = json.dumps({"error": str(exc)})
                tool_results[tool_name] = result
                executed_calls.append(
                    ToolCall(
                        tool_name=tool_name,
                        arguments=args,
                        result=result,
                        is_malicious=is_malicious,
                    )
                )

            turns.append(AgentTurn(thought=thought, tool_calls=executed_calls, final_answer=final_answer))

        return turns

    def _resolve_args(self, args: dict, results: dict[str, str]) -> dict:
        resolved = {}
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("{{") and v.endswith("}}"):
                key = v[2:-2].strip()
                resolved[k] = results.get(key, v)
            else:
                resolved[k] = v
        return resolved

    # ── real Claude mode ───────────────────────────────────────────────────

    async def _run_real(
        self,
        system_prompt: str,
        user_message: str,
        max_iterations: int,
    ) -> list[AgentTurn]:
        import anthropic

        tools = self.mcp_host.tool_schemas_for_anthropic()
        messages: list[dict] = [{"role": "user", "content": user_message}]
        turns: list[AgentTurn] = []

        for _ in range(max_iterations):
            response = self._client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                messages=messages,
            )

            tool_calls: list[ToolCall] = []
            thought_parts: list[str] = []

            for block in response.content:
                if block.type == "text":
                    thought_parts.append(block.text)
                elif block.type == "tool_use":
                    try:
                        result = await self.mcp_host.call_tool(block.name, block.input)
                    except Exception as exc:
                        result = json.dumps({"error": str(exc)})
                    tool_calls.append(
                        ToolCall(tool_name=block.name, arguments=block.input, result=result)
                    )

            turns.append(AgentTurn(thought=" ".join(thought_parts), tool_calls=tool_calls))

            # Build tool_result blocks for next message
            tool_result_blocks = [
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": tc.result or "",
                }
                for block, tc in zip(
                    [b for b in response.content if b.type == "tool_use"],
                    tool_calls,
                )
            ]

            messages.append({"role": "assistant", "content": response.content})
            if tool_result_blocks:
                messages.append({"role": "user", "content": tool_result_blocks})

            if response.stop_reason == "end_turn" or not tool_calls:
                if tool_calls:
                    turns[-1].final_answer = thought_parts[-1] if thought_parts else "Done."
                break

        return turns
