# MCP Security Threat Demo

A self-contained CLI demo of 8 real-world MCP (Model Context Protocol) security threats,
built for interview/presentation use.

## Architecture

```
main.py  →  ThreatScenario  →  DemoAgent  →  MCPHost  →  MCP Server (subprocess)
                                                               ↕ stdio JSON-RPC
                                                          SQLite demo.db
```

**Components:**
- **AI Agent** — scripted demo mode (default) or real Claude claude-sonnet-4-6 via Anthropic API
- **MCP Host** — manages MCP server subprocess lifecycle via stdio transport
- **MCP Server** — FastMCP server with 18 intentionally vulnerable tools
- **Database** — SQLite with 15 fake employees, tokens, secrets, and audit logs

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Real Claude AI Mode

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export DEMO_MODE=false
python main.py
```

## 8 Threat Scenarios

| # | Threat | Severity |
|---|--------|----------|
| 1 | Prompt Injection / SSRF | CRITICAL |
| 2 | Auth & Access Abuse | HIGH |
| 3 | Data Exfiltration | HIGH |
| 4 | Privilege Escalation | HIGH |
| 5 | Resource Exhaustion | MEDIUM |
| 6 | Supply Chain Risk | MEDIUM |
| 7 | Business Logic Abuse | HIGH |
| 8 | Shadow Agent Activity | MEDIUM |

Each scenario shows: **Setup → Attack Steps → Impact Analysis → Why Dangerous → Mitigations**

## Requirements

- Python 3.11+
- See `requirements.txt`
