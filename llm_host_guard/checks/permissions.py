"""Permission audit: are installed AI agents allowed to do more than they need to?
Reads agent/MCP config files. Evidence = tool, config path, rule id, variable NAMES. Never prints secret values or file contents."""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from llm_host_guard.core import Ctx, Finding
from llm_host_guard.checks import agents as ag

NAME = "permissions"
SECRET_KEY = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD", re.I)
RUNNERS = {"npx", "bunx", "uvx", "pipx"}
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def shown(ctx: Ctx, p: Path) -> str:
    try:
        return "~/" + str(p.relative_to(ctx.home))
    except ValueError:
        return str(p)


def is_broad(ctx: Ctx, scope: str) -> bool:
    s = scope.strip()
    if s == "~":
        return True
    n = os.path.normpath(os.path.expanduser(s.replace("~", str(ctx.home), 1)) if s.startswith("~") else s)
    home = os.path.normpath(str(ctx.home))
    return n in (home, os.path.dirname(home), "/", "\\") or bool(re.fullmatch(r"[A-Za-z]:[\\/]?", s))


def bypass_rules(cfg: dict) -> list[str]:
    """Settings that switch off the approval step, across the config shapes we know."""
    out = []
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions" or cfg.get("skipDangerousModePermissionPrompt") is True:
        out.append("bypass_prompts")
    if cfg.get("approval_policy") == "never" or cfg.get("sandbox_mode") == "danger-full-access":   # Codex CLI
        out.append("bypass_prompts")
    for a in perms.get("allow") or []:
        a = str(a).strip()
        if a == "Bash" or re.fullmatch(r"Bash\(\s*(\*+|:\*)?\s*\)", a):
            out.append("shell_wildcard")
    return list(dict.fromkeys(out))


def unpinned(entry: dict) -> str | None:
    cmd = Path(str(entry.get("command", ""))).name
    if cmd not in RUNNERS:
        return None
    args = [str(a) for a in entry.get("args") or []]
    if cmd == "pipx" and args and args[0] == "run":
        args = args[1:]
    pkg = next((a for a in args if not a.startswith("-")), "")
    if not pkg:
        return None
    pinned = ("@" in pkg.lstrip("@")) if cmd in ("npx", "bunx") else ("==" in pkg or "@" in pkg)
    return None if pinned else pkg


def audit_config(ctx: Ctx, tool: str, path: Path, cfg: dict, facts: dict) -> list[Finding]:
    out: list[Finding] = []
    where = shown(ctx, path)

    def add(sev, title, detail, fix, rule, **ev):
        out.append(Finding(NAME, sev, title, detail, fix, {"tool": tool, "config_path": where, "rule": rule, **ev},
                           fix_note="Config edits are your call, so this has no one-key fix."))

    for rule in bypass_rules(cfg):
        facts.setdefault(tool, set()).add(rule)
        if rule == "bypass_prompts":
            add("HIGH", f"{tool} is set to act without asking you first",
                "Approval prompts are switched off, so anything the agent decides to run, it runs.",
                "Turn the approval prompts back on in this config.", rule)
        else:
            add("HIGH", f"{tool} may run any command without asking",
                "A wildcard shell rule allows every command.", "Replace the wildcard with the few commands you actually use.", rule)
    has_secret = False
    for name, e in ag.mcp_entries(cfg).items():
        for scope in ag.fs_scopes(e):
            if is_broad(ctx, scope):
                add("HIGH", f"{tool}: the '{name}' file tool can reach your whole home folder or drive",
                    "A hijacked agent could read or change anything there, including keys and documents.",
                    "Point it at one project folder only.", "fs_scope_broad", server=name, scope=scope)
        env = e.get("env") if isinstance(e.get("env"), dict) else {}
        for var, val in env.items():
            if SECRET_KEY.search(str(var)) and isinstance(val, str) and val and not val.lstrip().startswith("$"):
                has_secret = True
                add("HIGH", f"{tool}: a secret ({var}) is saved in plain text in its config",
                    "Anyone or anything that can read this file gets the key.",
                    "Move the key to an environment variable or secret store and reference it as ${NAME}.",
                    "secret_in_config", server=name, var=var, len=len(val))
        pkg = unpinned(e)
        if pkg:
            add("MED", f"{tool}: the '{name}' tool downloads '{pkg}' fresh every time with no version fixed",
                "If that package is ever taken over, the new code runs on your machine next launch.",
                "Pin a version, for example name@1.2.3.", "unpinned_runner", server=name, package=pkg)
        url = str(e.get("url") or "")
        if url.startswith("http://") and (urlparse(url).hostname or "") not in LOOPBACK:
            add("MED", f"{tool}: the '{name}' tool talks to a remote server over unencrypted http",
                "Anyone on the network path can read or change what the agent sends and receives.", "Use https.",
                "http_remote", server=name)
    if has_secret and ctx.os != "Windows":
        try:
            if path.stat().st_mode & 0o044:
                add("MED", f"{tool}: its config file with a saved secret can be read by other users",
                    "File permissions let other accounts on this machine open it.", f"chmod 600 {path}", "config_world_readable")
        except OSError:
            pass
    return out


def audit(ctx: Ctx) -> tuple[list[Finding], dict]:
    """Returns (findings, {tool: {rule ids}}) cached on ctx so other checks reuse the parse."""
    cached = getattr(ctx, "_perm", None)
    if cached:
        return cached
    findings: list[Finding] = []
    facts: dict = {}
    seen: set = set()
    paths = []
    for t in ctx.signatures["agent_tools"]:
        paths += [(t["name"], ag.expand(ctx, p)) for p in t.get("mcp_config_paths", []) + t.get("settings_paths", [])]
    paths += [("MCP config", ag.expand(ctx, p)) for p in ctx.signatures.get("mcp_config_paths", [])]
    for tool, p in paths:
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        cfg = ag.read_config(p)
        if cfg:
            findings += audit_config(ctx, tool, p, cfg, facts)
    ctx._perm = (findings, facts)
    return ctx._perm


def run(ctx: Ctx) -> list[Finding]:
    if ctx.os == "Windows":
        return [Finding(NAME, "INFO", "Agent permissions are not checked on Windows yet")]
    findings, _ = audit(ctx)
    return findings or [Finding(NAME, "OK", "No risky agent permissions found")]
