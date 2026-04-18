"""Base classes shared by all threat scenario modules."""
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.mcp_host import MCPHost
from core.agent import DemoAgent
from core.display import (
    console,
    threat_header,
    setup_panel,
    agent_thought,
    tool_call_display,
    tool_result_display,
    impact_table,
    why_dangerous_panel,
    mitigations_panel,
    attack_begins_banner,
    step_panel,
    print_divider,
)


@dataclass
class ThreatMetadata:
    number: int
    name: str
    severity: str
    description: str
    attack_vector: str
    impact: str


class ThreatScenario(ABC):
    metadata: ThreatMetadata

    def __init__(self, mcp_host: MCPHost, demo_mode: bool = True):
        self.mcp_host = mcp_host
        self.agent = DemoAgent(mcp_host, demo_mode=demo_mode)
        self.demo_mode = demo_mode

    @abstractmethod
    async def run(self) -> None:
        """Execute the full threat scenario."""

    async def _display_turns(self, turns, malicious_tools: set[str] | None = None) -> None:
        malicious_tools = malicious_tools or set()
        for i, turn in enumerate(turns, 1):
            step_panel(i, turn.thought[:80] + ("..." if len(turn.thought) > 80 else ""))
            agent_thought(turn.thought)
            for tc in turn.tool_calls:
                await asyncio.sleep(0.1)
                tool_call_display(tc.tool_name, tc.arguments)
                if tc.result is not None:
                    is_bad = tc.is_malicious or tc.tool_name in malicious_tools
                    tool_result_display(tc.tool_name, tc.result, is_malicious=is_bad)
            if turn.final_answer:
                console.print(f"\n  [dim]Agent final answer: {turn.final_answer}[/dim]")
            console.print()
