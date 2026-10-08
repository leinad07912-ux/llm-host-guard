"""Agent inventory: which AI agents are installed / running here, what they can do, which MCP servers they load.
Detect + refer; constraining them lives in agent-firewall / mcp-sentinel. Reads config paths and flag names only,
never file contents beyond parsing MCP server entries (command, args, url, env KEY NAMES)."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from llm_host_guard.core import Ctx, Finding, sh

NAME = "agents"
MAX_CFG_BYTES = 1_000_000
MAX_ACTIVITY_FILES = 3000


def expand(ctx: Ctx, p: str) -> Path:
    return ctx.home / p.removeprefix("~/")


def read_json(path: Path) -> dict | None:
    try:
        if path.stat().st_size > MAX_CFG_BYTES:
            return None
        v = json.loads(path.read_text(errors="ignore"))
        return v if isinstance(v, dict) else None
    except (OSError, ValueError):
        return None


def read_toml(path: Path) -> dict | None:
    try:
        import tomllib
        if path.stat().st_size > MAX_CFG_BYTES:
            return None
        return tomllib.loads(path.read_text(errors="ignore"))
    except Exception:  # noqa: BLE001 - unreadable/invalid config must never break the scan
        return None


def read_config(path: Path) -> dict | None:
    return read_toml(path) if path.suffix == ".toml" else read_json(path)


def mcp_entries(cfg: dict) -> dict:
    """{server_name: entry} from the shapes used by Claude/Cursor/Gemini/Windsurf (mcpServers) and Codex (mcp_servers)."""
    out: dict = {}
    for key in ("mcpServers", "mcp_servers"):
        if isinstance(cfg.get(key), dict):
            out.update({k: v for k, v in cfg[key].items() if isinstance(v, dict)})
    for proj in (cfg.get("projects") or {}).values():   # Claude Code: per-project servers in ~/.claude.json
        if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
            out.update({k: v for k, v in proj["mcpServers"].items() if isinstance(v, dict)})
    return out


_FS_PKG = re.compile(r"server-filesystem|filesystem-mcp|mcp-server-filesystem", re.I)


def fs_scopes(entry: dict) -> list[str]:
    """Directories a filesystem MCP server is rooted at (its non-flag args after the package name)."""
    args = [str(a) for a in entry.get("args") or []]
    if not _FS_PKG.search(" ".join([str(entry.get("command", ""))] + args)):
        return []
    return [a for a in args if not a.startswith("-") and not _FS_PKG.search(a)
            and a not in ("npx", "uvx") and ("/" in a or "\\" in a or a == "~" or ":" in a)]


def summarize_mcp(entries: dict) -> list[dict]:
    out = []
    for name, e in entries.items():
        out.append({"name": name, "cmd": str(e.get("command") or e.get("url") or "")[:80], "scope": (fs_scopes(e) or [""])[0]})
    return out


def find_pids(table: dict, procs: list[str]) -> list[int]:
    want = {p.lower() for p in procs}
    return sorted(pid for pid, (_, comm) in table.items() if comm.lower() in want) if want else []


def parse_etime(s: str) -> int | None:
    """ps etime '[[dd-]hh:]mm:ss' → seconds."""
    m = re.fullmatch(r"\s*(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)\s*", s or "")
    if not m:
        return None
    d, h, mi, se = (int(x or 0) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + se


def uptime_s(pid: int) -> int | None:
    return parse_etime(sh(["ps", "-o", "etime=", "-p", str(pid)]) or "")


def last_active(ctx: Ctx, paths: list[str]) -> float | None:
    """Newest mtime among the tool's session/history paths (mtime only, files are never opened)."""
    newest, seen = None, 0
    for p in paths:
        root = expand(ctx, p)
        try:
            cands = [] if root.is_dir() else [root]   # directory mtimes move on any create/delete; only files count
            if root.is_dir():
                for dp, dns, fns in os.walk(root):
                    if len(Path(dp).relative_to(root).parts) >= 3:
                        dns[:] = []
                    cands += [Path(dp) / n for n in fns]
                    seen += len(fns)
                    if seen > MAX_ACTIVITY_FILES:
                        break
            for c in cands:
                m = c.stat().st_mtime
                newest = m if newest is None or m > newest else newest
        except OSError:
            continue
    return newest


def mcp_config_files(ctx: Ctx, tool: dict) -> list[Path]:
    return [p for p in (expand(ctx, x) for x in tool.get("mcp_config_paths", [])) if p.is_file()]


def inventory(ctx: Ctx, table: dict | None = None) -> list[dict]:
    """Installed or running agents, cached on ctx. `table` = {pid: (ppid, comm)} (injected in tests)."""
    if getattr(ctx, "_agents", None) is not None:
        return ctx._agents
    if table is None:
        from llm_host_guard.checks.runtime import proc_table
        table = proc_table()
    out = []
    for t in ctx.signatures["agent_tools"]:
        installed = any(expand(ctx, p).exists() for p in t["paths"])
        pids = find_pids(table, t.get("procs", []))
        if not (installed or pids):
            continue
        entries: dict = {}
        for f in mcp_config_files(ctx, t):
            entries.update(mcp_entries(read_config(f) or {}))
        la = last_active(ctx, t.get("activity_paths", []))
        out.append({
            "name": t["name"], "kind": t["kind"], "installed": installed, "running": bool(pids), "pids": pids[:10],
            "capabilities": t["capabilities"], "mcp_servers": summarize_mcp(entries), "_mcp_raw": entries,
            "last_active": datetime.fromtimestamp(la, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if la else None,
            "_last_active_ts": la,
        })
    extra = [p for p in (expand(ctx, x) for x in ctx.signatures.get("mcp_config_paths", [])) if p.is_file()]
    if extra:   # standalone MCP configs not tied to one agent
        entries = {}
        for f in extra:
            entries.update(mcp_entries(read_config(f) or {}))
        if entries:
            out.append({"name": "MCP config", "kind": "mcp_server", "installed": True, "running": False, "pids": [],
                        "capabilities": [], "mcp_servers": summarize_mcp(entries), "_mcp_raw": entries,
                        "last_active": None, "_last_active_ts": None})
    ctx._agents = out
    return out


def public(agents: list[dict]) -> list[dict]:
    """Report-safe view: drop private underscore fields."""
    return [{k: v for k, v in a.items() if not k.startswith("_")} for a in agents]


def run(ctx: Ctx, table: dict | None = None) -> list[Finding]:
    if ctx.os == "Windows":
        return [Finding(NAME, "INFO", "Agent inventory is not checked on Windows yet")]
    ag = inventory(ctx, table)
    if not ag:
        return [Finding(NAME, "OK", "No AI agent tooling detected", evidence={"agents": []})]
    running = [a["name"] for a in ag if a["running"]]
    names = ", ".join(a["name"] for a in ag)
    n_mcp = sum(len(a["mcp_servers"]) for a in ag)
    return [Finding(
        NAME, "INFO", f"{len(ag)} AI agent(s) on this machine: {names}",
        f"{len(running)} running now{(' (' + ', '.join(running) + ')') if running else ''}; {n_mcp} MCP server(s) configured. "
        "Agents with shell access turn a hidden instruction in a web page into a command on your computer.",
        "Review what each agent is allowed to do (see the permissions check) and close ones you are not using. "
        "Constrain actions with agent-firewall (https://github.com/leinad07912-ux/agent-firewall); scan MCP servers with mcp-sentinel.",
        {"agents": public(ag)},
    )]
