"""Agent tooling on the host. Detect + refer; don't duplicate agent-firewall / mcp-sentinel."""
from __future__ import annotations

from pathlib import Path

from core import Ctx, Finding

NAME = "agents"


def run(ctx: Ctx) -> list[Finding]:
    present = [t["name"] for t in ctx.signatures["agent_tools"]
               if any((ctx.home / p.removeprefix("~/")).exists() for p in t["paths"])]
    if not present:
        return [Finding(NAME, "OK", "No coding-agent tooling detected")]
    mcp_json = list(ctx.home.glob(".mcp.json")) + list(ctx.home.glob(".claude/**/mcp*.json"))
    return [Finding(
        NAME, "INFO", f"Agent tooling present: {', '.join(present)}",
        f"Agents with shell access turn prompt injection into host compromise. {len(mcp_json)} MCP config(s) found. "
        "This tool audits the LLM host surface only.",
        "Constrain agent actions with agent-firewall (https://github.com/leinad07912-ux/agent-firewall) and scan "
        "MCP servers/skills with mcp-sentinel.",
        {"tools": present, "mcp_configs": [str(p) for p in mcp_json[:20]]},
    )]
