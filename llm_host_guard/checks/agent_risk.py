"""Agent risk: idle agents (running but unused) and prompt-injection EXPOSURE.
Exposure is not detection: a host scanner cannot see an injection. It can see the setup that makes one costly,
an agent that reads untrusted content and also holds powerful tools. Wording is "exposed"/"could", never "protected"."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from llm_host_guard.core import Ctx, Finding, sh
from llm_host_guard.checks import agents as ag
from llm_host_guard.checks import permissions as perm

NAME = "agent_risk"
IDLE_DAYS = 3.0
IDLE_DAYS_SCREEN = 1.0
STATE = Path.home() / ".llm-host-guard" / "clients.json"   # per-port: first seen, last client seen
UNTRUSTED_CAPS = {"browser", "email", "web_fetch"}
POWERFUL_CAPS = {"shell", "fs_write", "keyboard_mouse", "screen"}
SCREEN_CAPS = {"screen", "keyboard_mouse"}
UNTRUSTED_MCP = re.compile(r"fetch|browser|playwright|puppeteer|web|mail|gmail|slack", re.I)


def clients_connected(port: int) -> int | None:
    out = sh(["ss", "-tnH", "state", "established", f"( sport = :{port} )"])
    return None if out is None else len([ln for ln in out.splitlines() if ln.strip()])


def idle_agents(ctx: Ctx, now: float, uptime=ag.uptime_s, idle_days: float | None = None,
                idle_days_screen: float | None = None) -> list[Finding]:
    idle_days = IDLE_DAYS if idle_days is None else idle_days
    idle_days_screen = IDLE_DAYS_SCREEN if idle_days_screen is None else idle_days_screen
    out = []
    for a in ag.inventory(ctx):
        la, ups = a["_last_active_ts"], [u for u in (uptime(p) for p in a["pids"]) if u is not None]
        if not (a["running"] and la and ups):   # unknown activity or uptime = never guess idle
            continue
        days = min(now - la, max(ups)) / 86400
        screen = bool(SCREEN_CAPS & set(a["capabilities"]))
        if days <= (idle_days_screen if screen else idle_days):
            continue
        ev = {"rule": "idle_agent", "tool": a["name"], "idle_days": round(days, 1), "pids": a["pids"]}
        if screen:
            out.append(Finding(NAME, "HIGH", f"{a['name']} can control the screen and has been idle for {days:.0f} day(s)",
                               "An agent that can move the mouse and type is waiting there with nobody watching.",
                               f"Close {a['name']} when you are not using it.", ev,
                               risk="Risk: a hidden instruction could make it click and type on your computer while you are away."))
        else:
            out.append(Finding(NAME, "MED", f"{a['name']} has been running but unused for {days:.0f} day(s)",
                               "Nothing has touched its history in that time.", f"Close {a['name']} until you need it.", ev))
    return out


def idle_model_servers(ctx: Ctx, now: float, state_path: Path, clients=clients_connected,
                       idle_days: float | None = None) -> list[Finding]:
    """Model server open to the network with no client for idle_days. Needs watch history: first run only records."""
    idle_days = IDLE_DAYS if idle_days is None else idle_days
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    out, live = [], set()
    for l in ctx.listeners:
        sig = ctx.sig_for(l)
        if not sig or l.loopback or not l.wildcard:
            continue
        live.add(str(l.port))
        s = state.setdefault(str(l.port), {"first": now, "last_client": 0})
        n = clients(l.port)
        if n:
            s["last_client"] = now
        if n is None:
            continue
        days = (now - max(s["first"], s["last_client"])) / 86400
        if days > idle_days:
            out.append(Finding(NAME, "HIGH", f"{sig['name']} is open to the network and nobody has used it for {days:.0f} day(s)",
                               "It answers anyone who can reach this machine, yet no one is actually using it.",
                               f"Stop {sig['name']} or bind it to this machine only.",
                               {"rule": "idle_agent", "tool": sig["name"], "port": l.port, "idle_days": round(days, 1)}))
    state = {k: v for k, v in state.items() if k in live}
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state))
    except OSError:
        pass
    return out


def injection_exposure(ctx: Ctx, facts: dict) -> list[Finding]:
    out = []
    for a in ag.inventory(ctx):
        if a["kind"] == "model_server":
            continue
        caps = set(a["capabilities"])
        mcp = [n for n, e in a["_mcp_raw"].items() if UNTRUSTED_MCP.search(n + " " + str(e.get("command", "")) + " " + " ".join(map(str, e.get("args") or [])))]
        untrusted = sorted(caps & UNTRUSTED_CAPS) + [f"mcp:{n}" for n in mcp]
        powerful = sorted(caps & POWERFUL_CAPS)
        if not (untrusted and powerful):
            continue
        off = "bypass_prompts" in facts.get(a["name"], set())
        ev = {"rule": "injection_exposure", "tool": a["name"], "untrusted": untrusted, "powerful": powerful,
              "prompts": "off" if off else "on"}
        base = (f"{a['name']} reads web or email content and can run commands or change files")
        if off:
            out.append(Finding(NAME, "HIGH", f"{base} with no approval step: a hidden instruction in a page could act on your computer",
                               "Content from outside can carry instructions the agent may follow. Nothing asks you first.",
                               "Switch the approval prompts back on.", ev,
                               risk="Risk: a hidden instruction in a web page or document could make it act on your computer."))
        else:
            out.append(Finding(NAME, "INFO", f"{base}; approval prompts are on, keep them on",
                               "Content from outside can carry instructions. The approval step is what stands between that and your files.",
                               "Keep approval prompts on and read each request before accepting.", ev))
    return out


def run(ctx: Ctx, now: float | None = None, state_path: Path | None = None, uptime=ag.uptime_s,
        clients=clients_connected) -> list[Finding]:
    if ctx.os == "Windows":
        return [Finding(NAME, "INFO", "Agent risk is not checked on Windows yet")]
    now = now or time.time()
    _, facts = perm.audit(ctx)
    out = idle_agents(ctx, now, uptime) + idle_model_servers(ctx, now, state_path or STATE, clients) + injection_exposure(ctx, facts)
    return out or [Finding(NAME, "OK", "No idle or injection-exposed agents found")]
