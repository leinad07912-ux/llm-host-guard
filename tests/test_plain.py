"""Plain-English gate: every say/todo/risk a person reads must be jargon-free and short. Run: python -m pytest tests/test_plain.py"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_host_guard import plain  # noqa: E402

# One real-looking title per rule family. A rule that stops matching its sample fails below.
SAMPLES = [
    ("ports", "CRITICAL", "Ollama on 0.0.0.0:11434 reachable from LAN with no auth (3 models listed)"),
    ("ports", "MED", "Ollama on 0.0.0.0:11434 open without auth, ufw-scoped to 10.0.0.5"),
    ("ports", "LOW", "Ollama on 0.0.0.0:11434 non-loopback, ufw-scoped to 10.0.0.5/32"),
    ("ports", "HIGH", "Ollama on 0.0.0.0:11434 bound to non-loopback"),
    ("ports", "OK", "2 LLM listener(s) found, all loopback-only"),
    ("docker", "HIGH", "container qdrant publishes 0.0.0.0:6333 — bypasses host firewall"),
    ("docker", "LOW", "container qdrant publishes 0.0.0.0:6333 but DOCKER-USER drops it"),
    ("docker", "MED", "DOCKER-USER chain is empty"),
    ("docker", "INFO", "DOCKER-USER chain unreadable without sudo"),
    ("exposure", "CRITICAL", "Host has a public IP (1.2.3.4)"),
    ("exposure", "HIGH", "Tunnel daemon running: cloudflared"),
    ("firewall", "HIGH", "ufw installed but disabled"),
    ("firewall", "HIGH", "ufw default policy is not deny incoming"),
    ("firewall", "HIGH", "ufw allows port 11434 (LLM) from Anywhere"),
    ("firewall", "HIGH", "nftables present but no input hook chain"),
    ("firewall", "HIGH", "Windows Firewall OFF on at least one profile"),
    ("firewall", "OK", "ufw active, default deny incoming, LLM ports scoped"),
    ("config", "HIGH", "sshd PasswordAuthentication yes"),
    ("config", "MED", "sshd PermitRootLogin enabled"),
    ("config", "HIGH", "OLLAMA_ORIGINS=* (any website can drive your Ollama)"),
    ("config", "HIGH", "OLLAMA_HOST=0.0.0.0 (all interfaces)"),
    ("config", "HIGH", "vLLM on :8000 without --api-key"),
    ("config", "MED", "Open WebUI signup may be enabled"),
    ("internet", "CRITICAL", "Shodan sees LLM port(s) [11434] open on your public IP 1.2.3.4"),
    ("internet", "HIGH", "Shodan sees 2 open port(s) on your public IP 1.2.3.4: [22, 80]"),
    ("internet", "CRITICAL", "Router UPnP forwards LLM port(s) to 192.168.1.5"),
    ("internet", "MED", "Router UPnP forwards 2 port(s) to this host: [8080, 22]"),
    ("runtime", "CRITICAL", "ollama opened connections to 40 different internet hosts in 2 min — looks like a scan"),
    ("runtime", "HIGH", "ollama hammered 1.2.3.4 25 times in 2 min — looks like brute force"),
    ("runtime", "CRITICAL", "Ollama (pid 12) spawned 'sh' (pid 99)"),
    ("runtime", "HIGH", "Ollama (pid 12) connected to an unrecognised internet address: 1.2.3.4:443"),
    ("models", "HIGH", "3 pickle-format weight file(s) — execute code on load"),
    ("models", "HIGH", "1 malformed model file(s)"),
    ("models", "MED", "2 world-writable model path(s)"),
    ("versions", "HIGH", "Ollama 0.1.30 has 2 known security issue(s)"),
    ("versions", "LOW", "Ollama is out of date (0.5.0, newest is 0.6.0)"),
    ("versions", "HIGH", "vllm 0.4.0 has 1 known CVE(s)"),
    ("agents", "INFO", "4 AI agent(s) on this machine: Claude Code, Cursor"),
    ("agent_risk", "HIGH", "Claude Code can control the screen and has been idle for 3 day(s)"),
    ("agent_risk", "MED", "Cursor has been running but unused for 5 day(s)"),
    ("agent_risk", "HIGH", "Ollama is open to the network and nobody has used it for 4 day(s)"),
    ("agent_risk", "HIGH", "Claude Code reads web or email content and can run commands or change files with no approval step: a hidden instruction in a page could act on your computer"),
    ("agent_risk", "INFO", "Claude Code reads web or email content and can run commands or change files; approval prompts are on, keep them on"),
    ("permissions", "HIGH", "Claude Code is set to act without asking you first"),
    ("permissions", "HIGH", "Claude Code may run any command without asking"),
    ("permissions", "HIGH", "Cursor: the 'filesystem' file tool can reach your whole home folder or drive"),
    ("permissions", "HIGH", "Cursor: a secret (GITHUB_TOKEN) is saved in plain text in its config"),
    ("permissions", "MED", "Cursor: the 'gh' tool downloads 'gh-tools' fresh every time with no version fixed"),
    ("permissions", "MED", "Cursor: the 'api' tool talks to a remote server over unencrypted http"),
    ("permissions", "MED", "Cursor: its config file with a saved secret can be read by other users"),
]
JARGON = re.compile(r"\b(ports?|ufw|firewall\w*|nftables|iptables|sudo|root|bind\w*|loopback|lan|wan|upnp|shodan|cve\w*|pickle\w*|mcp|"
                    r"injection|docker\w*|sshd|ssh|pid|api[- ]key|token|http|localhost|interfaces?|daemon|cmdline|payload|"
                    r"exploit\w*|vulnerabilit\w*|unauthenticated|auth|config(uration)?|endpoint|inference|llm|tcp|ip)\b", re.I)


def test_every_sample_has_a_plain_rule_and_no_jargon():
    for check, sev, title in SAMPLES:
        say, todo, risk = plain.say_for({"check": check, "severity": sev, "title": title})
        assert say and todo, f"no plain rule for: {title}"
        assert "{" not in say + todo, f"unfilled placeholder: {say} / {todo}"
        for label, text in (("say", say), ("todo", todo), ("risk", risk)):
            m = JARGON.search(text)
            assert not m, f"jargon '{m.group(0)}' in {label} for {title!r}: {text}"
            assert len(text) <= 190, f"{label} too long ({len(text)}) for {title!r}"


def test_generic_fallback_is_plain():
    for sev in ("CRITICAL", "HIGH", "MED"):
        say, todo, _ = plain.say_for({"check": "new_check", "severity": sev, "title": "Some brand-new technical thing"})
        assert say and todo and not JARGON.search(say + todo)


def test_apply_keeps_check_supplied_risk():
    f = plain.apply({"check": "agent_risk", "severity": "HIGH", "risk": "Risk: mine",
                     "title": "Cursor can control the screen and has been idle for 3 day(s)"})
    assert f["risk"] == "Risk: mine" and f["say"].startswith("Cursor can use your mouse")
