"""Docker port publishing bypasses ufw (DOCKER chain is evaluated before INPUT)."""
from __future__ import annotations

import re

from llm_host_guard.core import Ctx, Finding, sh

NAME = "docker"
# `docker ps` prints published ports as 0.0.0.0:54322->5432/tcp, but a RANGE as 0.0.0.0:6333-6334->6333-6334/tcp.
_MAP = re.compile(r"(\[[0-9a-fA-F:]+\]|[0-9.]+|\*):(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?/(tcp|udp)")
_WILD = ("0.0.0.0", "::", "[::]")


def parse_ps_full(text: str) -> list[tuple[str, str, int, int, str]]:
    """[(container, bind_addr, host_port, container_port, proto)]; a published range is expanded port by port."""
    out = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        for addr, h1, h2, c1, c2, proto in _MAP.findall(ports):
            hlo, hhi = int(h1), int(h2 or h1)
            clo = int(c1)
            for i in range(hhi - hlo + 1):
                out.append((name, addr, hlo + i, clo + i, proto))
    return out


def parse_ps(text: str) -> list[tuple[str, str, int]]:
    """[(container, bind_addr, host_port)] for published TCP ports."""
    return [(n, a, hp) for n, a, hp, _cp, proto in parse_ps_full(text) if proto == "tcp"]


def _drop_rule(iface: str, port: int) -> str:
    # --ctorigdstport matches the port the client dialled. A plain --dport on the published port only matches
    # when the container listens on the same port, because Docker rewrites the destination first.
    return f"DOCKER-USER -i {iface} -p tcp -m conntrack --ctorigdstport {port} --ctdir ORIGINAL -j DROP"


def run(ctx: Ctx) -> list[Finding]:
    ps = sh(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    if ps is None:
        return []
    out = []
    wild = sorted({(n, hp, cp) for n, a, hp, cp, proto in parse_ps_full(ps) if proto == "tcp" and a in _WILD})
    llm_ports = {p for sig in ctx.signatures["products"] for p in sig["ports"]}
    for name, port, cport in wild:
        uncovered = ctx.docker_user_uncovered(port, cport)
        ev = {"container": name, "port": port, "container_port": cport}
        if not uncovered:
            out.append(Finding(NAME, "LOW", f"container {name} publishes 0.0.0.0:{port} but DOCKER-USER drops it",
                               "DOCKER-USER drops it on every network interface of this machine "
                               f"({', '.join(ctx.external_ifaces())}), so it is reachable only from this host.",
                               "", ev))
            continue
        covered = sorted(i for i in ctx.external_ifaces() if i not in uncovered)
        sev = "CRITICAL" if port in llm_ports else "HIGH"
        partial = f" (your DOCKER-USER rule covers {', '.join(covered)} only)" if covered else ""
        out.append(Finding(
            NAME, sev,
            f"container {name} publishes 0.0.0.0:{port} — bypasses host firewall{partial}",
            "Docker inserts its own iptables rules ahead of ufw/firewalld; a published port is reachable "
            f"from the network regardless of host firewall policy. Still open on: {', '.join(uncovered)}."
            + (f" A rule on port {port} would not match anyway, because Docker rewrites the destination to "
               f"the container's port {cport} first." if cport != port else ""),
            f"Publish on loopback: `-p 127.0.0.1:{port}:{cport}`; or set "
            "`{\"ip\": \"127.0.0.1\"}` in /etc/docker/daemon.json; or drop it on each interface "
            "with a DOCKER-USER rule that matches the original port (`-m conntrack --ctorigdstport`).",
            ev,
            fix_cmds=[f"iptables -I {_drop_rule(i, port)}" for i in uncovered],
            undo_cmds=[f"iptables -D {_drop_rule(i, port)}" for i in uncovered],
            fix_note="live rules only; one per interface that faces a network. Persist via /etc/ufw/after.rules "
                     "(see examples/ufw-docker-user.rules) or iptables-persistent, then verify from ANOTHER device "
                     "on the network, because a rule that looks right can still match nothing",
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
