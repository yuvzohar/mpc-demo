"""
MCPHost — manages the MCP server subprocess lifecycle and provides a
simple call_tool() interface used by all threat scenario modules.
"""
import os
import sys
import asyncio
from typing import Any

import anyio
import anyio.abc

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Tool


class MCPHost:
    """
    Spawns the MCP server as a subprocess (stdio transport) and keeps the
    ClientSession open for the full demo session.  All 8 threat scenarios
    share this single long-lived connection.
    """

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        self._session: ClientSession | None = None
        self._ready = asyncio.Event()
        self._shutdown = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._available_tools: list[Tool] = []
        self._server_script = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "mcp_server",
            "server.py",
        )

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._ready.clear()
        self._shutdown.clear()
        self._task = asyncio.create_task(self._run_server())
        await self._ready.wait()
        tools_result = await self._session.list_tools()
        self._available_tools = tools_result.tools

    async def stop(self) -> None:
        self._shutdown.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, Exception):
                self._task.cancel()

    async def _run_server(self) -> None:
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[self._server_script, "--db-path", self.db_path],
        )
        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    # Keep alive until stop() is called
                    shutdown_event = asyncio.Event()
                    shutdown_task = asyncio.create_task(self._wait_for_shutdown(shutdown_event))
                    await asyncio.wait(
                        [shutdown_task],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
        except Exception:
            self._ready.set()  # unblock waiters on failure

    async def _wait_for_shutdown(self, _: asyncio.Event) -> None:
        await self._shutdown.wait()

    # ── public API ─────────────────────────────────────────────────────────

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        if self._session is None:
            raise RuntimeError("MCPHost not started — call await host.start() first")
        result = await self._session.call_tool(tool_name, arguments)
        if result.isError:
            content = result.content[0].text if result.content else "Unknown error"
            raise RuntimeError(f"Tool '{tool_name}' returned error: {content}")
        if result.content:
            return result.content[0].text
        return ""

    def list_tools(self) -> list[Tool]:
        return self._available_tools

    def tool_schemas_for_anthropic(self) -> list[dict]:
        """Convert MCP tool definitions to Anthropic tool-use format."""
        tools = []
        for t in self._available_tools:
            schema = t.inputSchema if t.inputSchema else {"type": "object", "properties": {}}
            tools.append({
                "name": t.name,
                "description": t.description or "",
                "input_schema": schema,
            })
        return tools

    # ── context manager ────────────────────────────────────────────────────

    async def __aenter__(self) -> "MCPHost":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()
