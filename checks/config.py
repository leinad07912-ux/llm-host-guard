"""Runtime + host config weaknesses: CORS *, 0.0.0.0 binds, missing API keys, SSH password auth."""
from __future__ import annotations

import re
from pathlib import Path

from core import Ctx, Finding, sh

NAME = "config"


def _ollama_env(ctx: Ctx) -> dict:
    for l in ctx.listeners:
        if "ollama" in l.proc.lower() and l.pid:
            return ctx.env_of_pid(l.pid)
    txt = sh(["systemctl", "show", "ollama", "-p", "Environment"]) or ""
    return dict(kv.split("=", 1) for kv in txt.replace("Environment=", "").split() if "=" in kv)


def _sshd() -> list[Finding]:
    out = []
    files = [Path("/etc/ssh/sshd_config")] + sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf"))
    text = ""
    for f in files:
        try:
            text += f.read_text(errors="ignore") + "\n"
        except OSError:
            continue
    if not text:
        return out
    eff = sh(["sshd", "-T"]) or text  # sshd -T only as root
    if re.search(r"^\s*passwordauthentication\s+yes", eff, re.I | re.M):
        out.append(Finding(NAME, "HIGH", "sshd PasswordAuthentication yes",
                           "Brute-forceable. AI-driven credential stuffing makes this worse, not better.",
                           "PasswordAuthentication no  (keep one key-based session open while testing)"))
    if re.search(r"^\s*permitrootlogin\s+(yes|without-password|prohibit-password)", eff, re.I | re.M):
        out.append(Finding(NAME, "MED", "sshd PermitRootLogin enabled", "", "PermitRootLogin no"))
    return out


def run(ctx: Ctx) -> list[Finding]:
    out = []
    env = _ollama_env(ctx)
    if env:
        origins = env.get("OLLAMA_ORIGINS", "")
        if "*" in origins:
            out.append(Finding(NAME, "HIGH", "OLLAMA_ORIGINS=* (any website can drive your Ollama)",
                               "With wildcard CORS, JavaScript on any page you visit can call localhost:11434 "
                               "from your browser — run prompts, pull/delete models, exfiltrate outputs.",
                               "Set OLLAMA_ORIGINS to the exact origins that need it (e.g. http://localhost:3000)."))
        scoped = [x for x in ctx.ufw_sources(11434) if x != "Anywhere"]
        if env.get("OLLAMA_HOST", "").startswith(("0.0.0.0", ":", "[::]")) and not scoped:
            out.append(Finding(NAME, "HIGH", f"OLLAMA_HOST={env['OLLAMA_HOST']} (all interfaces)",
                               "", "OLLAMA_HOST=127.0.0.1 unless LAN clients need it; then firewall to LAN."))
    for l in ctx.listeners:
        cmd = ctx.cmdline_of_pid(l.pid).lower() if l.pid else ""
        if not cmd:
            continue
        if "vllm" in cmd and "--api-key" not in cmd and not l.loopback:
            out.append(Finding(NAME, "HIGH", f"vLLM on :{l.port} without --api-key", "", "vllm serve ... --api-key <secret>"))
        if "llama-server" in cmd and "--api-key" not in cmd and not l.loopback:
            out.append(Finding(NAME, "HIGH", f"llama-server on :{l.port} without --api-key", "", "llama-server ... --api-key <secret>"))
        if ("open-webui" in cmd or "open_webui" in cmd) and "enable_signup=false" not in (str(ctx.env_of_pid(l.pid)).lower()):
            out.append(Finding(NAME, "MED", "Open WebUI signup may be enabled", "First visitor becomes admin; later visitors self-register.",
                               "ENABLE_SIGNUP=false after creating your admin"))
    out += _sshd()
    return out or [Finding(NAME, "OK", "No config weaknesses detected")]
