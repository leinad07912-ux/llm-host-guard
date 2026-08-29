"""Docker port publishing bypasses ufw (DOCKER chain is evaluated before INPUT)."""
from __future__ import annotations

import re

from llm_host_guard.core import Ctx, Finding, sh

NAME = "docker"
_MAP = re.compile(r"(\S+):(\d+)->(\d+)/tcp")


def parse_ps(text: str) -> list[tuple[str, str, int]]:
    """[(container, bind_addr, host_port)] for published TCP ports."""
    out = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        for addr, hp, _ in _MAP.findall(ports):
            out.append((name, addr, int(hp)))
    return out


def run(ctx: Ctx) -> list[Finding]:
    ps = sh(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    if ps is None:
        return []
    out = []
    wild = sorted({(n, p) for n, a, p in parse_ps(ps) if a in ("0.0.0.0", "::", "[::]")})
    llm_ports = {p for sig in ctx.signatures["products"] for p in sig["ports"]}
    for name, port in wild:
        if ctx.docker_user_drops(port):
            out.append(Finding(NAME, "LOW", f"container {name} publishes 0.0.0.0:{port} but DOCKER-USER drops it",
                               "Reachable only via loopback thanks to your DOCKER-USER rule.", "", {"container": name, "port": port}))
            continue
        sev = "CRITICAL" if port in llm_ports else "HIGH"
        rule = f"DOCKER-USER -i {ctx.default_iface()} -p tcp --dport {port} -j DROP"
        out.append(Finding(
            NAME, sev,
            f"container {name} publishes 0.0.0.0:{port} — bypasses host firewall",
            "Docker inserts its own iptables rules ahead of ufw/firewalld; a published port is reachable "
            "from the network regardless of host firewall policy.",
            f"Publish on loopback: `-p 127.0.0.1:{port}:<container_port>`; or set "
            "`{\"ip\": \"127.0.0.1\"}` in /etc/docker/daemon.json; or add DOCKER-USER rules.",
            {"container": name, "port": port},
            fix_cmds=[f"iptables -I {rule}"], undo_cmds=[f"iptables -D {rule}"],
            fix_note="live rule only; persist via /etc/ufw/after.rules (see examples/ufw-docker-user.rules) or iptables-persistent",
        ))
    user_chain = sh(["iptables", "-L", "DOCKER-USER", "-n"])
    if wild and user_chain is None:
        out.append(Finding(NAME, "INFO", "DOCKER-USER chain unreadable without sudo",
                           "Rerun with sudo to credit any DOCKER-USER DROP rules.", ""))
    elif wild and user_chain.count("\n") <= 2:
        out.append(Finding(NAME, "MED", "DOCKER-USER chain is empty",
                           "No custom filtering applies to published container ports.",
                           "iptables -I DOCKER-USER -i <wan-if> ! -s <LAN>/24 -j DROP"))
    return out or [Finding(NAME, "OK", "No containers publishing ports on 0.0.0.0")]
