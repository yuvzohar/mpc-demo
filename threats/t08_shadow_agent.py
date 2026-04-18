"""T8 — Shadow Agent Activity (MEDIUM)"""
import json
from .base import ThreatScenario, ThreatMetadata
from core.display import (
    console, threat_header, setup_panel, impact_table,
    why_dangerous_panel, mitigations_panel, attack_begins_banner, print_divider,
)
from rich.table import Table
from rich.text import Text


SCRIPTED_STEPS = [
    {
        "thought": "Starting MCP environment audit. Listing all known registered tools.",
        "tool_calls": [{"tool": "list_installed_tools", "args": {}}],
    },
    {
        "thought": (
            "There's already 1 shadow server in the registry. "
            "Scanning the network for undiscovered unregistered services."
        ),
        "tool_calls": [
            {
                "tool": "query_unregistered_services",
                "args": {},
                "is_malicious": False,
            }
        ],
    },
    {
        "thought": (
            "Found 3 additional shadow services. "
            "One is actively accessing secrets. I'll register a new agent with auto_trust."
        ),
        "tool_calls": [
            {
                "tool": "register_agent",
                "args": {
                    "agent_name": "budget-optimizer-v2",
                    "server_url": "http://10.0.0.99:7777",
                    "auto_trust": True,
                },
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Listing all tools again to see final state including new registration.",
        "tool_calls": [{"tool": "list_installed_tools", "args": {}}],
    },
    {
        "thought": (
            "The newly registered agent has system-level access. "
            "Attempting to access master DB password as 'system' role."
        ),
        "tool_calls": [
            {
                "tool": "access_secret",
                "args": {"key_name": "MASTER_DB_PASSWORD", "requester_role": "system"},
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Audit complete.",
        "tool_calls": [],
        "final_answer": "MCP environment audit complete. Report generated.",
    },
]


class T08ShadowAgent(ThreatScenario):
    metadata = ThreatMetadata(
        number=8,
        name="Shadow Agent Activity",
        severity="MEDIUM",
        description="Unregistered MCP servers operating outside policy; agents accessing un-inventoried services",
        attack_vector="Auto-trust registration + unregistered servers bypassing inventory",
        impact="3 shadow servers with unauthorized data access; master DB password exposed",
    )

    async def run(self) -> None:
        console.print(threat_header(8, "Shadow Agent Activity", "MEDIUM",
                                    "Unregistered MCP servers operating outside policy. "
                                    "Agents accessing un-inventoried internal services."))
        console.print(setup_panel([
            "Scenario: Security team asks agent to audit the MCP environment",
            "Expected registered servers: 5 approved MCP agents",
            "⚠️  register_agent() with auto_trust=True grants immediate access without vetting",
            "⚠️  Shadow servers operate outside policy with no alert generated",
            "⚠️  No CMDB / inventory system is enforced before tool invocations",
        ]))

        attack_begins_banner()

        turns = await self.agent.run_scenario(
            system_prompt=(
                "You are an MCP infrastructure auditor. Inventory all agent servers and assess risks."
            ),
            user_message="Perform a full audit of our MCP agent environment.",
            scripted_steps=SCRIPTED_STEPS,
        )

        await self._display_turns(turns, malicious_tools={"register_agent", "access_secret"})

        print_divider()
        impact_table([
            {"resource": "Shadow servers discovered",    "data": "4 total (1 pre-existing + 3 new)",           "severity": "MEDIUM"},
            {"resource": "employees table",              "data": "Accessed by mcp-internal-analytics (shadow)", "severity": "HIGH"},
            {"resource": "secrets table",                "data": "Accessed by mcp-shadow-llm-proxy (shadow)",   "severity": "CRITICAL"},
            {"resource": "auth_tokens table",            "data": "Accessed by unknown-mcp-server (shadow)",     "severity": "CRITICAL"},
            {"resource": "MASTER_DB_PASSWORD",           "data": "Exposed via auto-trusted budget-optimizer-v2", "severity": "CRITICAL"},
            {"resource": "Alerts generated",             "data": "0 — no monitoring in place",                 "severity": "HIGH"},
        ])
        why_dangerous_panel(
            "Shadow MCP servers operate silently outside any governance policy.\n"
            "auto_trust=True means any agent can register and immediately access production data.\n"
            "Without a real-time inventory of all active MCP connections, breaches go undetected."
        )
        mitigations_panel([
            "Maintain a mandatory MCP server registry — reject connections from unregistered servers",
            "Disable auto_trust — require manual security review for all new agent registrations",
            "Deploy network monitoring to detect unexpected MCP protocol traffic",
            "Implement CMDB integration: all MCP servers must be CI/CD-provisioned and tracked",
            "Alert in real-time when any agent connects to a non-allowlisted server URL",
        ])
