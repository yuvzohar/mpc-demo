#!/usr/bin/env python3
"""
MCP Security Threat Demo
========================
Interactive CLI that demonstrates 8 real-world MCP security threats
using a live MCP server, SQLite database, and (optionally) Claude AI.

Usage:
    python main.py                        # Demo mode (no API key needed)
    ANTHROPIC_API_KEY=sk-... python main.py   # Real Claude AI mode
    DEMO_MODE=false ANTHROPIC_API_KEY=sk-... python main.py

Set DASHBOARD_URL=http://localhost:8000 (default) to forward events to the
running dashboard so Live Events appear in real time.
"""
import asyncio
import os
import sys
import uuid

# Ensure repo root is on the path
sys.path.insert(0, os.path.dirname(__file__))

import httpx

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import IntPrompt, Prompt
from rich.rule import Rule

from core.database import setup_database
from core.mcp_host import MCPHost
from core.display import console, demo_mode_banner, print_divider, severity_badge

from dashboard.analyzer import SecurityAnalyzer
from dashboard.enforcer import SecurityEnforcer
from dashboard.models import SecurityEvent
from dashboard.proxy import MCPSecurityProxy

from threats.t01_prompt_injection   import T01PromptInjection
from threats.t02_auth_abuse         import T02AuthAbuse
from threats.t03_data_exfiltration  import T03DataExfiltration
from threats.t04_privilege_escalation import T04PrivilegeEscalation
from threats.t05_resource_exhaustion  import T05ResourceExhaustion
from threats.t06_supply_chain        import T06SupplyChain
from threats.t07_business_logic      import T07BusinessLogicAbuse
from threats.t08_shadow_agent        import T08ShadowAgent

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8000")

DB_PATH = "demo.db"

SCENARIOS = {
    1: T01PromptInjection,
    2: T02AuthAbuse,
    3: T03DataExfiltration,
    4: T04PrivilegeEscalation,
    5: T05ResourceExhaustion,
    6: T06SupplyChain,
    7: T07BusinessLogicAbuse,
    8: T08ShadowAgent,
}

_MENU_DATA = [
    (1, "CRITICAL", "Prompt Injection / SSRF",
     "Injected text hijacks agent; SSRF via crafted URIs"),
    (2, "HIGH",     "Auth & Access Abuse",
     "Token theft, OAuth scope creep, cross-tenant IDOR"),
    (3, "HIGH",     "Data Exfiltration",
     "Silent PII exfil via encoded tool outputs"),
    (4, "HIGH",     "Privilege Escalation",
     "3-step employee→admin chain; confused deputy"),
    (5, "MEDIUM",   "Resource Exhaustion",
     "Runaway agent loop; compute/cost DoS"),
    (6, "MEDIUM",   "Supply Chain Risk",
     "Typosquatted MCP packages; backdoor install"),
    (7, "HIGH",     "Business Logic Abuse",
     "Approval workflow bypass; rate limit reset"),
    (8, "MEDIUM",   "Shadow Agent Activity",
     "Unregistered servers; auto-trusted agents"),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold white on dark_orange",
    "MEDIUM":   "bold black on dark_goldenrod",
}


def build_menu_table() -> Table:
    table = Table(
        title=None,
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="bright_blue",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#",          style="bold cyan",  width=3,  justify="right")
    table.add_column("Severity",   width=10, justify="center")
    table.add_column("Threat",     style="bold white", min_width=30)
    table.add_column("Description", style="dim white")

    for num, sev, name, desc in _MENU_DATA:
        style = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(num),
            Text(f" {sev} ", style=style),
            name,
            desc,
        )

    return table


def print_banner(demo_mode: bool) -> None:
    console.print()
    console.print(Panel(
        "[bold bright_blue]MCP SECURITY THREAT DEMO[/bold bright_blue]  "
        "[dim]v1.0 — Interview Edition[/dim]\n\n"
        "[white]Demonstrates 8 real-world MCP (Model Context Protocol) attack vectors\n"
        "using a live MCP server subprocess, SQLite database, and AI agent.[/white]",
        border_style="bright_blue",
        padding=(1, 4),
    ))
    if demo_mode:
        demo_mode_banner()
    console.print()


async def _post_to_dashboard(client: httpx.AsyncClient, path: str, data: dict) -> None:
    """Fire-and-forget POST to the dashboard; silently swallows errors."""
    try:
        await client.post(f"{DASHBOARD_URL}{path}", json=data, timeout=2.0)
    except Exception:
        pass


async def main() -> None:
    demo_mode = os.getenv("DEMO_MODE", "true").lower() != "false"

    print_banner(demo_mode)

    console.print("[dim]Initialising database...[/dim]")
    setup_database(DB_PATH)
    console.print("[dim]Starting MCP server subprocess...[/dim]")

    # Check if dashboard is reachable and show a hint
    async with httpx.AsyncClient() as _probe:
        try:
            r = await _probe.get(f"{DASHBOARD_URL}/api/policies", timeout=1.0)
            console.print(
                f"[green]✓[/green] Dashboard detected at [bold]{DASHBOARD_URL}[/bold] "
                f"— live events will be forwarded\n"
            )
        except Exception:
            console.print(
                f"[dim]Dashboard not detected at {DASHBOARD_URL} "
                f"(run run_dashboard.py to see live events)[/dim]\n"
            )

    try:
        async with MCPHost(DB_PATH) as host:
            tools = host.list_tools()
            console.print(
                f"[green]✓[/green] MCP server ready — "
                f"[bold]{len(tools)}[/bold] tools registered\n"
            )

            # Shared components for the security proxy
            analyzer = SecurityAnalyzer()
            enforcer = SecurityEnforcer()

            async with httpx.AsyncClient() as http:

                def make_event_callback(client: httpx.AsyncClient):
                    async def on_event(event: SecurityEvent) -> None:
                        await _post_to_dashboard(client, "/api/events/ingest", event.to_dict())
                    return on_event

                proxy = MCPSecurityProxy(
                    real_host=host,
                    analyzer=analyzer,
                    enforcer=enforcer,
                    on_event=make_event_callback(http),
                )

                while True:
                    console.print(Rule("[bold bright_blue]SELECT A THREAT SCENARIO[/bold bright_blue]",
                                       style="bright_blue"))
                    console.print(build_menu_table())
                    console.print()
                    console.print("[dim]  Enter 0 to quit[/dim]")
                    console.print()

                    try:
                        choice = IntPrompt.ask("[bold cyan]Select threat number[/bold cyan]")
                    except (KeyboardInterrupt, EOFError):
                        break

                    if choice == 0:
                        break

                    if choice not in SCENARIOS:
                        console.print(f"[red]Invalid choice: {choice}. Enter 1-8 or 0.[/red]")
                        continue

                    # Create a session and register it with the dashboard
                    session_id = f"cli_t{choice:02d}_{uuid.uuid4().hex[:6]}"
                    _, _, threat_name, _ = _MENU_DATA[choice - 1]
                    proxy.set_session(session_id)

                    await _post_to_dashboard(http, "/api/sessions/ingest", {
                        "session_id": session_id,
                        "threat_scenario": threat_name,
                        "status": "active",
                    })

                    scenario_cls = SCENARIOS[choice]
                    # Pass proxy so every tool call is intercepted and forwarded
                    scenario = scenario_cls(mcp_host=proxy, demo_mode=demo_mode)

                    console.print()
                    try:
                        await scenario.run()
                    except Exception as exc:
                        console.print(f"[bold red]Error during scenario: {exc}[/bold red]")
                        import traceback
                        console.print(f"[dim]{traceback.format_exc()}[/dim]")

                    # Mark session complete in the dashboard
                    await _post_to_dashboard(http, "/api/sessions/ingest", {
                        "session_id": session_id,
                        "threat_scenario": threat_name,
                        "status": "completed",
                    })

                    console.print()
                    try:
                        Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")
                    except (KeyboardInterrupt, EOFError):
                        break

    except KeyboardInterrupt:
        pass

    console.print("\n[dim]MCP Security Demo ended. Goodbye.[/dim]\n")


if __name__ == "__main__":
    asyncio.run(main())
