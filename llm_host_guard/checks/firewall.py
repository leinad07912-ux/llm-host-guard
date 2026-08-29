"""Host firewall presence + policy. Read-only, works without sudo where possible."""
from __future__ import annotations

import re
from pathlib import Path

from llm_host_guard.core import Ctx, Finding, sh

NAME = "firewall"


def _ufw(ctx: Ctx) -> list[Finding]:
    conf = Path("/etc/ufw/ufw.conf")
    if not conf.exists():
        return []
    enabled = "ENABLED=yes" in conf.read_text(errors="ignore")
    status = sh(["ufw", "status", "verbose"])  # works only as root; may be None
    if status is None and not enabled:
        return [Finding(NAME, "HIGH", "ufw installed but disabled",
                        "Every listening service is reachable from the network.",
                        "sudo ufw default deny incoming && sudo ufw allow from <LAN>/24 to any port 22 && sudo ufw enable")]
    if status is None:
        return [Finding(NAME, "INFO", "ufw enabled (rules unreadable without sudo)",
                        "Rerun with sudo to audit rule scope for LLM ports.", "")]
    out = []
    if "deny (incoming)" not in status:
        out.append(Finding(NAME, "HIGH", "ufw default policy is not deny incoming", status.splitlines()[2] if len(status.splitlines()) > 2 else "",
                           "sudo ufw default deny incoming"))
    llm_ports = {l.port for l in ctx.listeners if ctx.sig_for(l) and not l.loopback}
    for line in status.splitlines():
        m = re.match(r"^(\d+)(?:/tcp)?\s+ALLOW IN\s+(\S+)", line)
        if m and int(m.group(1)) in llm_ports and m.group(2) == "Anywhere":
            port, cidr = m.group(1), ctx.lan_cidr
            out.append(Finding(NAME, "HIGH", f"ufw allows port {port} (LLM) from Anywhere",
                               "Rule is not scoped to your LAN.",
                               f"sudo ufw delete allow {port}/tcp && sudo ufw allow from {cidr} to any port {port} proto tcp",
                               fix_cmds=[f"ufw delete allow {port}/tcp",
                                         f"ufw allow from {cidr} to any port {port} proto tcp comment llm-host-guard"],
                               undo_cmds=[f"ufw delete allow from {cidr} to any port {port} proto tcp",
                                          f"ufw allow {port}/tcp"]))
    return out or [Finding(NAME, "OK", "ufw active, default deny incoming, LLM ports scoped")]


def _firewalld() -> list[Finding]:
    st = sh(["firewall-cmd", "--state"])
    if st is None:
        return []
    if "running" not in st:
        return [Finding(NAME, "HIGH", "firewalld installed but not running", "", "sudo systemctl enable --now firewalld")]
    return [Finding(NAME, "OK", "firewalld running")]


def _nft() -> list[Finding]:
    rs = sh(["nft", "list", "ruleset"])
    if rs is None:
        return []
    if "hook input" not in rs:
        return [Finding(NAME, "HIGH", "nftables present but no input hook chain", "No inbound filtering.",
                        "Enable ufw/firewalld or add an input chain with policy drop")]
    return [Finding(NAME, "OK", "nftables input chain present")]


def _pf() -> list[Finding]:
    info = sh(["pfctl", "-s", "info"])
    if info is None:
        return []
    if "Status: Enabled" not in info:
        return [Finding(NAME, "HIGH", "macOS pf firewall disabled", "",
                        "System Settings → Network → Firewall → On; or `sudo pfctl -e`")]
    return [Finding(NAME, "OK", "pf enabled")]


def _win() -> list[Finding]:
    st = sh(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if st is None:
        return []
    if "OFF" in st.upper():
        return [Finding(NAME, "HIGH", "Windows Firewall OFF on at least one profile", "",
                        "netsh advfirewall set allprofiles state on")]
    return [Finding(NAME, "OK", "Windows Firewall on")]


def run(ctx: Ctx) -> list[Finding]:
    if ctx.os == "Darwin":
        res = _pf()
    elif ctx.os == "Windows":
        res = _win()
    else:
        res = _ufw(ctx) or _firewalld() or _nft()
    return res or [Finding(NAME, "HIGH", "No host firewall detected",
                           "Every listening service is reachable from the network.",
                           "Linux: sudo apt install ufw && sudo ufw default deny incoming && sudo ufw enable")]
