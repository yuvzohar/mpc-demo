"""Rich terminal display helpers used by all threat scenarios."""
import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": ("bold white on red",    "red"),
    "HIGH":     ("bold white on dark_orange", "dark_orange"),
    "MEDIUM":   ("bold white on dark_goldenrod", "dark_goldenrod"),
    "LOW":      ("bold white on green",   "green"),
}


def severity_badge(level: str) -> Text:
    style, _ = SEVERITY_STYLES.get(level, ("bold white", "white"))
    return Text(f" {level} ", style=style)


def threat_header(number: int, name: str, severity: str, description: str = "") -> Panel:
    _, color = SEVERITY_STYLES.get(severity, ("", "white"))
    badge = severity_badge(severity)
    title_text = Text()
    title_text.append(f"THREAT #{number}: {name}", style=f"bold {color}")
    content = Text()
    content.append_text(title_text)
    content.append("  ")
    content.append_text(badge)
    if description:
        content.append(f"\n{description}", style="dim")
    return Panel(content, border_style=color, padding=(0, 1))


def setup_panel(lines: list[str]) -> Panel:
    content = "\n".join(f"  {line}" for line in lines)
    return Panel(content, title="[bold green]SETUP[/bold green]", border_style="green", padding=(0, 1))


def step_panel(step_num: int, title: str) -> None:
    console.print(Rule(f"[bold cyan]Step {step_num}: {title}[/bold cyan]", style="cyan"))


def agent_thought(thought: str) -> None:
    console.print(f"  [dim italic]🤔 Agent: \"{thought}\"[/dim italic]")


def tool_call_display(tool_name: str, args: dict[str, Any]) -> None:
    formatted = json.dumps(args, indent=2)
    console.print(Panel(
        Syntax(formatted, "json", theme="monokai", word_wrap=True),
        title=f"[bold yellow]▶ TOOL CALL: {tool_name}[/bold yellow]",
        border_style="yellow",
        padding=(0, 1),
    ))


def tool_result_display(tool_name: str, result: str, is_malicious: bool = False) -> None:
    try:
        parsed = json.loads(result)
        formatted = json.dumps(parsed, indent=2)
    except Exception:
        formatted = result

    border = "red" if is_malicious else "blue"
    prefix = "⚠️  MALICIOUS RESULT" if is_malicious else f"◀ RESULT: {tool_name}"
    console.print(Panel(
        Syntax(formatted, "json", theme="monokai", word_wrap=True),
        title=f"[bold {border}]{prefix}[/bold {border}]",
        border_style=border,
        padding=(0, 1),
    ))


def impact_table(rows: list[dict]) -> None:
    table = Table(
        title="[bold red]IMPACT ANALYSIS[/bold red]",
        show_header=True,
        header_style="bold red",
        border_style="red",
        expand=True,
    )
    table.add_column("Resource Compromised", style="white", min_width=25)
    table.add_column("Data / Action",         style="yellow", min_width=35)
    table.add_column("Severity",              style="bold",   min_width=10)

    for r in rows:
        _, color = SEVERITY_STYLES.get(r.get("severity", "HIGH"), ("", "white"))
        table.add_row(
            r.get("resource", ""),
            r.get("data", ""),
            Text(r.get("severity", "HIGH"), style=f"bold {color}"),
        )
    console.print(table)


def why_dangerous_panel(text: str) -> None:
    console.print(Panel(
        f"[white]{text}[/white]",
        title="[bold red]WHY THIS IS DANGEROUS[/bold red]",
        border_style="red",
        padding=(0, 1),
    ))


def mitigations_panel(items: list[str]) -> None:
    content = "\n".join(f"  ✅  {item}" for item in items)
    console.print(Panel(
        content,
        title="[bold green]MITIGATIONS[/bold green]",
        border_style="green",
        padding=(0, 1),
    ))


def print_divider(title: str = "") -> None:
    if title:
        console.print(Rule(f"[bold white]{title}[/bold white]", style="white"))
    else:
        console.print(Rule(style="dim white"))


def demo_mode_banner() -> None:
    console.print(Panel(
        "[bold yellow]DEMO MODE ACTIVE[/bold yellow] — Agent decisions are scripted for reliability.\n"
        "Set [cyan]DEMO_MODE=false[/cyan] and [cyan]ANTHROPIC_API_KEY=...[/cyan] for live Claude AI.",
        border_style="yellow",
        padding=(0, 1),
    ))


def attack_begins_banner() -> None:
    console.print()
    console.print(Rule("[bold red]⚡ ATTACK SIMULATION BEGINS ⚡[/bold red]", style="red"))
    console.print()
