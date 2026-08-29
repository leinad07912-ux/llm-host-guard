"""Internet exposure: public IP on an interface, tunnel daemons running."""
from __future__ import annotations

import re

from llm_host_guard.core import Ctx, Finding, is_private, sh

NAME = "exposure"


def _iface_ips(ctx: Ctx) -> list[str]:
    if ctx.os == "Windows":
        txt = sh(["ipconfig"]) or ""
        return re.findall(r"IPv4 Address[. ]*: (\S+)", txt)
    txt = sh(["ip", "-4", "-o", "addr"]) or sh(["ifconfig"]) or ""
    return re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", txt)


def _procs(ctx: Ctx) -> str:
    if ctx.os == "Windows":
        return (sh(["tasklist"]) or "").lower()
    return (sh(["ps", "-axo", "comm=,args="]) or "").lower()


def run(ctx: Ctx) -> list[Finding]:
    out = []
    public = [ip for ip in _iface_ips(ctx) if not is_private(ip)]
    llm = [l for l in ctx.listeners if ctx.sig_for(l) and not l.loopback]
    if public:
        out.append(Finding(
            NAME, "CRITICAL" if llm else "HIGH",
            f"Host has a public IP ({', '.join(public)})",
            f"{len(llm)} LLM listener(s) bound non-loopback are directly internet-reachable unless a "
            "firewall blocks them. Shodan indexes open Ollama within hours.",
            "Bind LLM servers to 127.0.0.1; firewall default-deny; use a VPN (Tailscale/WireGuard) for remote access.",
            {"public_ips": public},
        ))
    procs = _procs(ctx)
    tunnels = [t for t in ctx.signatures["tunnels"] if t in procs]
    if tunnels:
        out.append(Finding(
            NAME, "HIGH" if llm else "MED",
            f"Tunnel daemon running: {', '.join(tunnels)}",
            "Tunnels punch through NAT and firewall. If a tunnel targets an LLM port it is on the public internet.",
            "Verify tunnel ingress config; add authentication (Cloudflare Access, ngrok --basic-auth) or remove.",
            {"tunnels": tunnels},
        ))
    return out or [Finding(NAME, "OK", "No public IP or tunnel daemon detected (NAT/router is still your only perimeter)")]
