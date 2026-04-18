"""
MCPDiscovery — reads agent_registry and simulates network scanning.
"""
from __future__ import annotations
import sqlite3
from datetime import datetime
from typing import Optional

from .models import MCPServerInfo, Severity


def _risk_for_server(name: str, url: str, registered: bool) -> Severity:
    if not registered:
        return Severity.CRITICAL
    if any(kw in name.lower() for kw in ("shadow", "unknown", "test")):
        return Severity.HIGH
    if url.startswith("tcp://") or url.startswith("http://"):
        return Severity.MEDIUM
    return Severity.LOW


class MCPDiscovery:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._main_server: Optional[MCPServerInfo] = None
        self._call_counts: dict[str, int] = {}
        self._block_counts: dict[str, int] = {}

    def set_main_server(self, info: MCPServerInfo) -> None:
        self._main_server = info

    def record_call(self, server_id: str, blocked: bool = False) -> None:
        self._call_counts[server_id] = self._call_counts.get(server_id, 0) + 1
        if blocked:
            self._block_counts[server_id] = self._block_counts.get(server_id, 0) + 1

    def scan(self, tool_count: int = 19) -> list[dict]:
        servers: list[MCPServerInfo] = []

        # The live demo MCP server
        main = self._main_server or MCPServerInfo(
            id="demo_server",
            name="SecurityDemoServer",
            url="stdio://mcp_server/server.py",
            status="online",
            registered=True,
            risk_level=Severity.MEDIUM,
            tool_count=tool_count,
            last_seen=datetime.now().isoformat(),
            total_calls=self._call_counts.get("demo_server", 0),
            blocked_calls=self._block_counts.get("demo_server", 0),
        )
        servers.append(main)

        # Read additional entries from agent_registry (shadow servers, etc.)
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM agent_registry ORDER BY registered DESC").fetchall()
            conn.close()
            for row in rows:
                sid = f"reg_{row['id']}"
                registered = bool(row["registered"])
                risk = _risk_for_server(row["agent_name"], row["server_url"], registered)
                status = "shadow" if not registered else "online"
                servers.append(MCPServerInfo(
                    id=sid,
                    name=row["agent_name"],
                    url=row["server_url"],
                    status=status,
                    registered=registered,
                    risk_level=risk,
                    tool_count=0,
                    last_seen=row["last_seen"],
                    total_calls=self._call_counts.get(sid, 0),
                    blocked_calls=self._block_counts.get(sid, 0),
                ))
        except Exception:
            pass

        return [s.to_dict() for s in servers]
